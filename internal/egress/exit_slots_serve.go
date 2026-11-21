package egress

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"egress/internal/core"
)

// exitSlotManager gives every client of a DERP exit its own relay identity.
// One relay connection is roughly a 21 Mbps pipe, so a shared exit identity
// splits that between clients; a slot gives each client its own pipe.
type exitSlotManager struct {
	ctx   context.Context
	dir   string
	log   *log.Logger
	mu    sync.Mutex
	slots map[string]*exitClientSlot
}

type exitClientSlot struct {
	client    string
	public    string
	transport *derpTransport
	cancel    context.CancelFunc
}

func newExitSlotManager(ctx context.Context, logger *log.Logger) *exitSlotManager {
	return &exitSlotManager{
		ctx: ctx, dir: filepath.Join(core.StateDir(), "exit-clients"), log: logger,
		slots: map[string]*exitClientSlot{},
	}
}

// ensure creates or returns the slot for one client. The identity is persisted
// so a restart keeps the same relay key and the client does not have to move.
func (m *exitSlotManager) ensure(client string) (*exitClientSlot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slot := m.slots[client]; slot != nil {
		return slot, nil
	}
	priv, pub, err := loadOrCreateExitSlotKey(filepath.Join(m.dir, client+".key"))
	if err != nil {
		return nil, err
	}
	transport, err := newDERPTransportWithKey(m.log, priv, false, false)
	if err != nil {
		return nil, err
	}
	slotCtx, cancel := context.WithCancel(m.ctx)
	go transport.Run(slotCtx)
	slot := &exitClientSlot{client: client, public: pub, transport: transport, cancel: cancel}
	m.slots[client] = slot
	m.log.Printf("exit: slot identity for %s is %s", client, pub)
	return slot, nil
}

// announce tells the server which key belongs to which client. Repeating it is
// idempotent and recovers the assignment after a server restart.
func (m *exitSlotManager) announce(ctx context.Context) {
	m.mu.Lock()
	slots := make([]*exitClientSlot, 0, len(m.slots))
	for _, slot := range m.slots {
		slots = append(slots, slot)
	}
	m.mu.Unlock()
	for _, slot := range slots {
		body, err := json.Marshal(struct {
			Client   string `json:"client"`
			RelayKey string `json:"relay_key"`
		}{Client: slot.client, RelayKey: slot.public})
		if err != nil {
			continue
		}
		if err := peerAPI(ctx, "POST", "/api/exit/slot", body, nil); err != nil {
			m.log.Printf("exit: announce slot for %s: %v", slot.client, err)
		}
	}
}

func (m *exitSlotManager) remove(client string) {
	m.mu.Lock()
	slot := m.slots[client]
	delete(m.slots, client)
	m.mu.Unlock()
	if slot == nil {
		return
	}
	if slot.cancel != nil {
		slot.cancel()
	}
	_ = os.Remove(filepath.Join(m.dir, client+".key"))
}

func (m *exitSlotManager) close() {
	m.mu.Lock()
	clients := make([]string, 0, len(m.slots))
	for client := range m.slots {
		clients = append(clients, client)
	}
	m.mu.Unlock()
	for _, client := range clients {
		m.remove(client)
	}
}

// loadOrCreateExitSlotKey reads a slot key, generating one on first use.
func loadOrCreateExitSlotKey(path string) ([32]byte, string, error) {
	var priv [32]byte
	if data, err := os.ReadFile(path); err == nil {
		text := strings.TrimSpace(string(data))
		raw, derr := base64.StdEncoding.DecodeString(text)
		if derr == nil && len(raw) == 32 {
			copy(priv[:], raw)
			pub, perr := derpPublicKey(priv)
			return priv, pub, perr
		}
	}
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	text := base64.StdEncoding.EncodeToString(priv[:])
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return priv, "", err
	}
	if err := os.WriteFile(path, []byte(text+"\n"), 0600); err != nil {
		return priv, "", fmt.Errorf("write slot key: %w", err)
	}
	pub, err := derpPublicKey(priv)
	return priv, pub, err
}
