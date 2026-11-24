package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"egress/internal/core"
	"egress/internal/split"
)

// peerExitInfo is one exit another device in the circle is offering.
type peerExitInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Transport string `json:"transport"`
	Endpoint  string `json:"endpoint"`
	Path      string `json:"path"`
	PubKey    string `json:"pubkey"`
	RelayKey  string `json:"relay_key"`
}

// peerExitPrefPath is the opt-in marker. Peer exits are off by default: using
// one sends blocked traffic through a friend's connection, which is a choice
// the person using it should make.
func peerExitPrefPath() string {
	return filepath.Join(filepath.Dir(core.DeviceIdentityPath()), "prefer-peer-exit")
}

// peerExitChoicePath pins one offered exit by id. An empty file means the
// first exit in the server's order, which is the default.
func peerExitChoicePath() string {
	return filepath.Join(filepath.Dir(core.DeviceIdentityPath()), "peer-exit-id")
}

func peerExitChoice() string {
	data, err := os.ReadFile(peerExitChoicePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func peerExitPreferred() bool {
	_, err := os.Stat(peerExitPrefPath())
	return err == nil
}

// cmdPeerExit turns the preference on or off and reports what it would use.
func cmdPeerExit(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: egress peer-exit on|off|status")
	}
	switch args[0] {
	case "on":
		if err := os.MkdirAll(filepath.Dir(peerExitPrefPath()), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(peerExitPrefPath(), []byte("on\n"), 0644); err != nil {
			return err
		}
		fmt.Println("peer exits enabled; blocked traffic will use one from your circle when a device offers it")
		return nil
	case "off":
		if err := os.Remove(peerExitPrefPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("peer exits disabled; blocked traffic will use the published exit")
		return nil
	case "use":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return errors.New("usage: egress peer-exit use <exit-id>")
		}
		id := strings.TrimSpace(args[1])
		if err := os.MkdirAll(filepath.Dir(peerExitChoicePath()), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(peerExitChoicePath(), []byte(id+"\n"), 0644); err != nil {
			return err
		}
		fmt.Printf("preferred peer exit: %s\n", id)
		return nil
	case "auto":
		if err := os.Remove(peerExitChoicePath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("peer exit choice cleared; the first offered exit is used")
		return nil
	case "status":
		state := "off"
		if peerExitPreferred() {
			state = "on"
		}
		fmt.Printf("peer exits: %s\n", state)
		if choice := peerExitChoice(); choice != "" {
			fmt.Printf("preferred: %s\n", choice)
		} else {
			fmt.Println("preferred: auto")
		}
		exits, err := fetchPeerExits(context.Background())
		if err != nil {
			return err
		}
		if len(exits) == 0 {
			fmt.Println("no exits offered in this circle")
			return nil
		}
		for _, e := range exits {
			label := e.Label
			if label == "" {
				label = e.ID
			}
			where := e.Endpoint
			if e.Transport == "derp" {
				where = "derp " + e.RelayKey
			}
			fmt.Printf("%-12s %-24s %s\n", e.ID, where, label)
		}
		return nil
	default:
		return fmt.Errorf("unknown peer-exit action %q; use on, off or status", args[0])
	}
}

// peerExitPoller keeps the manager's peer exit list and the server's record of
// which exit this device uses in step. It runs even when the preference is off
// so turning it on takes effect within a tick, without a restart.
type peerExitPoller struct {
	direct   *directExit
	log      *log.Logger
	used     string
	withdrew bool
}

func newPeerExitPoller(direct *directExit, logger *log.Logger) *peerExitPoller {
	return &peerExitPoller{direct: direct, log: logger}
}

func (p *peerExitPoller) Run(ctx context.Context) {
	p.refresh(ctx)
	tick := time.NewTicker(45 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			p.withdraw(context.Background())
			return
		case <-tick.C:
		}
		p.refresh(ctx)
	}
}

func (p *peerExitPoller) refresh(ctx context.Context) {
	if !peerExitPreferred() {
		p.withdraw(ctx)
		p.direct.SetPeerExits(nil, false)
		return
	}
	exits, err := fetchPeerExits(ctx)
	if err != nil {
		p.log.Printf("peer exits: %v", err)
		return
	}
	if len(exits) == 0 {
		p.withdraw(ctx)
		p.direct.SetPeerExits(nil, false)
		return
	}
	chosen := exits[0]
	if want := peerExitChoice(); want != "" {
		for _, e := range exits {
			if e.ID == want {
				chosen = e
				break
			}
		}
	}
	// The direct exit manager uses the first entry, so put the chosen exit
	// there and keep the rest as fallbacks.
	list := make([]split.DirectExit, 0, len(exits))
	add := func(e peerExitInfo) {
		list = append(list, split.DirectExit{
			ID: e.ID, Label: e.Label, Transport: e.Transport,
			Endpoint: e.Endpoint, Path: e.Path, PubKey: e.PubKey, RelayKey: e.RelayKey,
		})
	}
	add(chosen)
	for _, e := range exits {
		if e.ID != chosen.ID {
			add(e)
		}
	}
	p.direct.SetPeerExits(list, true)
	// Announce on every refresh: the record is idempotent, and re-sending it
	// recovers the exit's peer list after a server restart.
	if err := announceExitUse(ctx, chosen.ID); err != nil {
		p.log.Printf("peer exits: announce use: %v", err)
		return
	}
	if chosen.ID != p.used {
		p.log.Printf("peer exits: using %s (%s)", chosen.ID, chosen.Endpoint)
		p.used = chosen.ID
	}
	p.withdrew = false
}

func (p *peerExitPoller) withdraw(ctx context.Context) {
	// One delete per transition, including on a fresh process whose preference
	// is already off. The server may still hold a use from a previous run.
	if p.withdrew && p.used == "" {
		return
	}
	if err := withdrawExitUse(ctx); err != nil {
		p.log.Printf("peer exits: withdraw: %v", err)
		return
	}
	p.used = ""
	p.withdrew = true
}

func fetchPeerExits(ctx context.Context) ([]peerExitInfo, error) {
	out := struct {
		Exits []peerExitInfo `json:"exits"`
	}{}
	if err := peerAPI(ctx, http.MethodGet, "/api/peer-exits", nil, &out); err != nil {
		return nil, err
	}
	return out.Exits, nil
}

func announceExitUse(ctx context.Context, exitID string) error {
	body, _ := json.Marshal(struct {
		Exit string `json:"exit"`
	}{Exit: exitID})
	return peerAPI(ctx, http.MethodPost, "/api/exit/use", body, nil)
}

func withdrawExitUse(ctx context.Context) error {
	return peerAPI(ctx, http.MethodDelete, "/api/exit/use", nil, nil)
}

// peerAPI calls an authenticated peer endpoint. The device credential is used
// when it exists; the bound device key is the fallback.
func peerAPI(ctx context.Context, method, path string, body []byte, out any) error {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://bypass.breadway.dev"+path, reader)
	if err != nil {
		return err
	}
	applyPeerAuth(req, devicePubkey())
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: core.ControlDialContext,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
