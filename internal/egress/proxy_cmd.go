package egress

import (
	"context"
	"egress/internal/split"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// Set at build time for delivery clients:
//
//	go build -ldflags "-X main.embeddedSocksUser=... -X main.embeddedSocksPass=..."
var (
	embeddedSocksUser string
	embeddedSocksPass string
)

// cmdProxy runs the per-user split proxy and, on Windows, its tray.
func cmdProxy(args []string) (err error) {
	fs := newFlagSet("proxy")
	listen := fs.String("listen", "127.0.0.1:1081", "local CONNECT proxy and PAC address")
	relay := fs.String("relay", "127.0.0.1:1080", "local wstunnel forward to the Aegis SOCKS relay")
	authPath := fs.String("socks-auth", filepath.Join(split.ProfileDir(), "socks-auth"), "file with user:password for the relay")
	userFlag := fs.String("socks-user", "", "relay username (overrides the auth file)")
	passFlag := fs.String("socks-pass", "", "relay password (overrides the auth file)")
	tray := fs.Bool("tray", false, "show the Windows tray icon")
	startRelay := fs.Bool("start-relay", false, "start wstunnel for the Aegis SOCKS relay")
	install := fs.Bool("install", false, "write the per-user autostart entry (Windows)")
	debug := fs.Bool("debug", false, "trace commands and log to a file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	// A proxy started at login has no console, so a fatal error would
	// otherwise vanish. Record it where the next report can see it.
	defer func() {
		if err != nil {
			appLogger().Printf("proxy: %v", err)
		}
	}()

	user, pass := resolveSocksAuth(*authPath, *userFlag, *passFlag)
	if *install {
		if user == "" || pass == "" {
			return errors.New("--install needs relay credentials: pass --socks-user and --socks-pass")
		}
		if err := writeSocksAuth(*authPath, user, pass); err != nil {
			return err
		}
		if err := installProxyAutostart(*authPath, *relay); err != nil {
			return err
		}
		fmt.Println("installed per-user autostart")
	}
	if user == "" || pass == "" {
		appLogger().Printf("proxy: no relay credentials; blocked destinations will fail")
	}

	plat := newPlatform()
	_, gateway, err := plat.DefaultRoute()
	if err != nil {
		appLogger().Printf("proxy: no default route yet (%v)", err)
	}
	p := split.NewProxy(split.NetworkKey("", gateway), split.ProfileDir(), *listen, *relay, user, pass, appLogger())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *startRelay {
		stopRelay, err := startSocksRelay(ctx, *relay)
		if err != nil {
			return fmt.Errorf("start relay: %w", err)
		}
		defer stopRelay()
	}

	if *tray {
		// The tray is decoration. Serving must not depend on it: creating the
		// icon can fail in an elevated or session-0 context, and when it took
		// the process down with it the machine lost its proxy entirely
		// (EGRESS-102).
		go func() {
			if err := runTray(ctx, p); err != nil && ctx.Err() == nil {
				appLogger().Printf("proxy: tray unavailable: %v", err)
			}
		}()
	}
	appLogger().Printf("proxy: serving PAC and CONNECT on %s", *listen)
	return p.Serve(ctx)
}

func resolveSocksAuth(path, user, pass string) (string, string) {
	if user == "" && pass == "" {
		user, pass = embeddedSocksUser, embeddedSocksPass
	}
	if user != "" && pass != "" {
		return user, pass
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return user, pass
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if u, p, ok := strings.Cut(line, ":"); ok {
			return u, p
		}
	}
	return user, pass
}

// startSocksRelay runs the embedded wstunnel client for the SOCKS relay. It is
// the same binary and TLS path as the WireGuard fallback, only a different
// remote mapping.
func startSocksRelay(ctx context.Context, relayAddr string) (func(), error) {
	path, err := findWstunnel()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, "client",
		"--http-upgrade-path-prefix", "socks",
		"--dns-resolver", "dns://"+dohListenAddr,
		"--dns-resolver-prefer-ipv4",
		"--tls-verify-certificate",
		"-L", "tcp://"+relayAddr+":127.0.0.1:7109",
		"wss://"+dohHost,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}, nil
}

func writeSocksAuth(path, user, pass string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(user+":"+pass+"\n"), 0600)
}
