package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Set at build time:
//
//	go build -ldflags "-X main.embeddedKey=... -X main.embeddedClientIP=... -X main.buildVersion=..."
var (
	embeddedKey          string
	embeddedClientIP     string
	embeddedDefaultSplit string
	buildVersion         string
)

// defaultDebug is set to "true" at build time for delivery builds where the
// recipient cannot be relied on to pass --debug (see build.sh --debug-build).
// There is no opt-out flag: a debug-default binary always logs. Rebuild
// without the flag for a quiet binary.
var defaultDebug = "false"

// resolveDebug ORs an explicit --debug flag with the build-time default.
func resolveDebug(cmdline bool) bool {
	return cmdline || defaultDebug == "true"
}

func reportVersion() string {
	if buildVersion == "" {
		return "dev"
	}
	return buildVersion
}

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintf(os.Stderr, "egress: %v\n", err)
		os.Exit(1)
	}
}

func realMain() error {
	args := os.Args[1:]

	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			usage()
			return nil
		}
	}

	command := "install"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	switch command {
	case "install":
		return cmdInstall(args)
	case "supervise":
		return cmdSupervise(args)
	case "verify":
		return cmdVerify(args)
	case "probe":
		return cmdProbe(args)
	case "proxy":
		return cmdProxy(args)
	case "update":
		return cmdUpdate(args)
	case "update-sign":
		return cmdUpdateSign(args)
	case "update-keygen":
		return cmdUpdateKeygen(args)
	case "update-apply":
		return cmdUpdateApply(args)
	case "split-user":
		return cmdSplitUser(args)
	case "diagnose":
		return cmdDiagnose(args)
	case "pubkey", "key":
		return cmdPubkey(args)
	case "disable":
		return cmdDisable(args)
	case "enable":
		return cmdEnable(args)
	case "remove", "uninstall":
		return cmdRemove(args)
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Print(`egress: DNS over HTTPS resolver and WireGuard exit.

Usage:
  egress [command] [flags]

Commands:
  install      configure this machine (default)
  supervise    run the resolver and the fallback supervisor; used by the boot service
  verify       check the installed setup
  diagnose     print routing, DNS, tunnel and log state
  probe        classify domains over the direct path (split-mode foundation)
  proxy        run the per-user split proxy and PAC (Windows split mode)
  update       check for or apply a signed update over the tunnel
  update-sign  sign a release manifest (publisher side)
  update-keygen make an Ed25519 update signing key
  disable      stop now, restore DNS, and do not start at boot; keep the config
  enable       let it start at boot again and start it now
  remove       remove every installed part, including configs, logs and wstunnel
  uninstall    alias for remove
  pubkey       print the public key for a key, change nothing

install flags:
  --key <base64>      private key (fallback: the embedded key, then a prompt)
  --key-file <path>   read the private key from a file
  --ip <addr>         tunnel address for this device (default 10.88.0.4)
  --no-tunnel         DNS only
  --no-fallback       never use the WebSocket fallback
  --debug             trace every command and its output, and log to a file

disable, enable, remove and uninstall also accept --debug.

Build with a key compiled in:
  ./build.sh --generate --ip 10.88.0.4 --os windows
`)
}

func cmdInstall(args []string) error {
	return runInstall(newPlatform(), args)
}

func runInstall(plat platform, args []string) (err error) {
	fs := newFlagSet("install")
	keyFlag := fs.String("key", "", "private key")
	keyFile := fs.String("key-file", "", "file containing the private key")
	ipFlag := fs.String("ip", "", "tunnel address for this device")
	noTunnel := fs.Bool("no-tunnel", false, "configure DNS only")
	noFallback := fs.Bool("no-fallback", false, "never use the WebSocket fallback")
	split := fs.Bool("split", false, "route only learned-blocked destinations through the tunnel")
	noSplit := fs.Bool("no-split", false, "override a build that defaults to split mode")
	keepConfig := fs.Bool("keep-config", false, "reuse the existing tunnel key and address (upgrade)")
	debug := fs.Bool("debug", false, "trace commands and log to a file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *split && *noTunnel {
		return errors.New("--split needs the tunnel; it cannot be combined with --no-tunnel")
	}
	if *keepConfig && *noTunnel && runtime.GOOS != "windows" {
		return errors.New("--keep-config needs the tunnel config; it cannot be combined with --no-tunnel")
	}
	if embeddedDefaultSplit == "true" && !*noSplit {
		*split = true
	}
	if *split && runtime.GOOS == "windows" {
		// Windows split is the proxy/PAC path: the supervisor only serves DNS
		// and no WireGuard interface is installed.
		*noTunnel = true
	}
	setupLogging(resolveDebug(*debug))

	if err := plat.RequirePrivilege(); err != nil {
		return err
	}

	// Validate everything that can fail without touching the system before
	// stopping the running supervisor: while the old service is up, DNS
	// keeps working, so a bad key, address or missing route must refuse
	// before changing anything.
	iface, gateway, err := plat.DefaultRoute()
	if err != nil {
		return fmt.Errorf("find the default route: %w", err)
	}

	tcfg := tunnelConfig{ClientIP: defaultClientIP, Endpoint: aegisIPv4 + ":" + aegisWGPort}
	if validIPv4(embeddedClientIP) {
		tcfg.ClientIP = embeddedClientIP
	}
	if *ipFlag != "" {
		tcfg.ClientIP = *ipFlag
	}

	var keepKey string
	if *keepConfig {
		var keepIP string
		keepKey, keepIP, err = existingTunnelConfig()
		if err != nil {
			return fmt.Errorf("--keep-config: %w", err)
		}
		if *ipFlag == "" {
			tcfg.ClientIP = keepIP
		}
		// Preserve split mode across the upgrade.
		if splitEnabled() {
			*split = true
		}
	}
	tcfg.Split = *split
	// Split Windows installs and generic updates have no private key in this
	// invocation. Recover the public half from the build or the identity file
	// so install reports still identify the device.
	if *split && tcfg.PrivateKey == "" {
		if embeddedKey != "" {
			if pub, err := publicKey(embeddedKey); err == nil {
				tcfg.ReportPubkey = pub
				_ = saveDeviceIdentity(deviceIdentity{Pubkey: pub, IP: tcfg.ClientIP})
			}
		}
		if tcfg.ReportPubkey == "" {
			if id, err := loadDeviceIdentity(); err == nil {
				tcfg.ReportPubkey = id.Pubkey
				if *ipFlag == "" && id.IP != "" {
					tcfg.ClientIP = id.IP
				}
			}
		}
	}
	if !validIPv4(tcfg.ClientIP) {
		return fmt.Errorf("invalid tunnel address %q", tcfg.ClientIP)
	}

	var pub string
	if !*noTunnel {
		var key string
		if *keepConfig && *keyFlag == "" && *keyFile == "" {
			key = keepKey
		} else {
			key, err = resolveKey(*keyFlag, *keyFile)
			if err != nil {
				return err
			}
		}
		tcfg.PrivateKey = key
		pub, err = publicKey(key)
		if err != nil {
			return err
		}
		tcfg.ReportPubkey = pub
		_ = saveDeviceIdentity(deviceIdentity{Pubkey: pub, IP: tcfg.ClientIP})
	}

	// The marker must match the tunnel config. Track whether the config has
	// been written: a failure before that point restores the previous mode,
	// a failure after it leaves the marker matching the file on disk.
	prevSplit := splitEnabled()
	wroteConfig := false
	defer func() {
		if err != nil && !wroteConfig {
			_ = setSplitEnabled(prevSplit)
		}
	}()

	if *noTunnel {
		debugf("dns-only install: skipping wireguard-tools")
	} else if err := plat.InstallTools(); err != nil {
		return err
	}

	// Stop an older supervisor before replacing files it may be executing.
	// wstunnel.exe cannot be overwritten while it is running on Windows.
	_ = plat.StopService()

	// From here on, every failure must leave DNS working. Once the new unit
	// is installed the park path owns recovery; before that, put the previous
	// service back so an early exit cannot strand the resolver on a dead
	// listener. A parked install must not be restarted here, because parking
	// has already restored the machine to its pre-install state.
	pastInstallService := false
	parked := false
	defer func() {
		if err != nil && !pastInstallService && !parked {
			debugf("install failed before the new service; restarting the previous service")
			_ = plat.StartService()
		}
	}()

	// Deliver an older spooled install report before doing anything else.
	flushPendingReport()

	fmt.Printf("interface %s, gateway %s\n", iface, gateway)

	if !*noTunnel {
		fmt.Printf("\npublic key: %s\n", pub)
		fmt.Printf("add it on Aegis with allowed-ips %s/32 before this device will work\n\n", tcfg.ClientIP)
	}

	if !*noTunnel {
		changed, err := plat.WriteTunnelConfig(tcfg)
		if err != nil {
			return err
		}
		// The config and the mode marker must agree. Write the marker only
		// once the config is on disk; from here on a failure leaves both in
		// the requested mode instead of splitting them.
		if err := setSplitEnabled(*split); err != nil {
			return err
		}
		wroteConfig = true
		if changed {
			// New or different identity: bounce a live tunnel so it runs
			// the just-written config. StartTunnel alone is a no-op when
			// a tunnel is already up, which would leave the old key live
			// while verification reports the new one.
			debugf("tunnel config changed; restarting the tunnel")
			if err := plat.StopTunnel(); err != nil {
				return err
			}
		} else {
			debugf("tunnel config unchanged; keeping the live tunnel")
		}
		if err := plat.StartTunnel(); err != nil {
			return err
		}
		// Prove the running tunnel is the configured one. A failed stop
		// underneath a passing start leaves the old identity live, and the
		// Aegis peer alone cannot tell the two apart.
		if err := checkTunnelIdentity(plat, tcfg); err != nil {
			parked = true
			parkInstall(plat, tcfg, runChecks(plat, tcfg), err)
			return err
		}
		fmt.Println("wireguard tunnel is up")
		if *split {
			fmt.Println("split mode: only learned-blocked destinations will use the tunnel")
		}
	}

	if _, err := plat.InstallWstunnel(); err != nil {
		if !*noFallback {
			fmt.Fprintf(os.Stderr, "warning: wstunnel unavailable, the fallback will not work: %v\n", err)
		}
	}

	exe, err := ensureInstalledBinary()
	if err != nil {
		return err
	}
	// Lock the install directory in every mode, including --no-tunnel: it
	// always holds the installed binary, whose embedded key is recoverable
	// with strings. Fail closed rather than leave it permissive.
	if err := plat.SecureInstallDir(); err != nil {
		return fmt.Errorf("secure install directory: %w", err)
	}
	// The boot service and the scheduled task both reference this exact path,
	// which is always the permanent install location regardless of where the
	// user ran this command from.
	fmt.Printf("installed to %s; the boot service will run it from there\n", exe)

	// Arm the update check before the steps that can fail on a platform
	// quirk. A failure below then leaves an install that picks the fix up by
	// itself instead of a machine that needs another download.
	if err := installUpdateTimer(updatePollInterval); err != nil {
		debugf("early update check not armed: %v", err)
	}

	serviceArgs := []string{"supervise"}
	if *noTunnel {
		serviceArgs = append(serviceArgs, "--no-tunnel")
	}
	if *noFallback {
		serviceArgs = append(serviceArgs, "--no-fallback")
	}
	if resolveDebug(*debug) {
		serviceArgs = append(serviceArgs, "--debug")
	}

	if err := plat.InstallService(exe, serviceArgs); err != nil {
		return err
	}
	// The new unit is on disk: from here the rollback path owns recovery.
	pastInstallService = true
	// Drop any marker from a previous attempt: only this start may satisfy
	// the readiness check, otherwise a marker up to readyMarkerMaxAge old can
	// name a pid that has since exited (EGRESS-93).
	removeReadyMarker()
	if err := plat.StartService(); err != nil {
		return err
	}

	if err := waitForPort(dohListenAddr, 25*time.Second); err != nil {
		parkInstall(plat, tcfg, runChecks(plat, tcfg), fmt.Errorf("%w (run `egress diagnose`)", err))
		return fmt.Errorf("%w (run `egress diagnose`)", err)
	}
	// The port answering does not prove it is us: a foreign resolver already
	// on 7103 satisfies every probe while our service crash-loops. Require
	// the service active with a fresh marker from this start.
	if err := checkSupervisorLive(plat, readyMarkerMaxAge); err != nil {
		parkInstall(plat, tcfg, runChecks(plat, tcfg), err)
		return fmt.Errorf("supervisor is not healthy: %w (run `egress diagnose`)", err)
	}
	if err := plat.ApplyDNS(iface, gateway); err != nil {
		parkInstall(plat, tcfg, runChecks(plat, tcfg), err)
		return err
	}
	time.Sleep(500 * time.Millisecond)

	fmt.Println()
	if err := verifyAll(plat, tcfg, false); err != nil {
		// Networking goes back to its pre-install state first, so a failed
		// install never leaves the user offline, then the install parks for
		// the next release. The report carries what went wrong.
		parkInstall(plat, tcfg, runChecks(plat, tcfg), err)
		fmt.Fprintln(os.Stderr, "verification failed; run `egress diagnose`")
		fmt.Fprintln(os.Stderr, "networking is back to normal; the install stays and will update itself")
		return err
	}

	if *split && runtime.GOOS == "windows" {
		if err := configureWindowsSplit(); err != nil {
			fmt.Fprintf(os.Stderr, "split client setup failed: %v\n", err)
			parkInstall(plat, tcfg, runChecks(plat, tcfg), err)
			return err
		}
		if err := setSplitEnabled(true); err != nil {
			return err
		}
	}
	if err := installUpdateTimer(updatePollInterval); err != nil {
		fmt.Fprintf(os.Stderr, "warning: update timer not installed: %v\n", err)
	}

	results := describeSplit(runChecks(plat, tcfg), tcfg)
	if data, err := buildReport(tcfg, results, nil, false); err == nil {
		if err := sendReport(data); err != nil {
			debugf("install report unsent, spooled: %v", err)
			spoolReport(data)
		}
	}
	fmt.Println("\nall checks passed")
	return nil
}

// updatePollInterval is how often every install looks for a release, healthy
// or parked. The cost is one small HTTPS request, and it means a published fix
// lands within a minute instead of waiting for a daily window.
const updatePollInterval = time.Minute

// parkInstall handles a failed install without discarding it. Networking goes
// back to its pre-install state and the service stops, so a broken resolver is
// never the system resolver, but the binary and configs stay and the update
// check is armed at parkUpdateInterval. The next published release therefore
// installs itself: no download, no user action. Reporting is best effort and
// never masks the original error.
func parkInstall(plat platform, tcfg tunnelConfig, results checkResults, cause error) {
	results = describeSplit(results, tcfg)
	if err := plat.Disable(); err != nil {
		fmt.Fprintf(os.Stderr, "park: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "networking restored; the install is parked until a fixed release lands")
	}
	if err := installUpdateTimer(updatePollInterval); err != nil {
		fmt.Fprintf(os.Stderr, "park: update check not armed, the next release needs a manual install: %v\n", err)
	}
	data, err := buildReport(tcfg, results, cause, true)
	if err != nil {
		return
	}
	if err := sendReport(data); err != nil {
		debugf("failure report unsent, spooled: %v", err)
		spoolReport(data)
	}
}

func cmdSupervise(args []string) error {
	fs := newFlagSet("supervise")
	noTunnel := fs.Bool("no-tunnel", false, "do not manage the tunnel")
	noFallback := fs.Bool("no-fallback", false, "never use the WebSocket fallback")
	debug := fs.Bool("debug", false, "trace commands and log to a file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	plat := newPlatform()
	if err := plat.RequirePrivilege(); err != nil {
		return err
	}

	iface, gateway, err := plat.DefaultRoute()
	if err != nil {
		appLogger().Printf("no default route yet (%v); will keep trying", err)
	}

	resolver := newDoHResolver(gateway, appLogger())

	wstPath := ""
	if !*noTunnel && !*noFallback {
		if path, err := plat.WstunnelPath(); err == nil {
			wstPath = path
		} else {
			appLogger().Printf("wstunnel not found, the fallback is unavailable: %v", err)
		}
	}
	wst := newWstunnelProc(wstPath, appLogger())

	var split *splitController
	if splitEnabled() && !*noTunnel {
		split = newSplitController(NetworkKey("", gateway), iface,
			newRouteManager(wgInterface, appLogger()), appLogger())
	}
	sup := newSupervisor(plat, resolver, wst, appLogger(), !*noTunnel, !*noFallback)
	sup.iface, sup.gateway = iface, gateway
	sup.split = split

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return sup.Run(ctx)
}

func cmdVerify(args []string) error {
	fs := newFlagSet("verify")
	debug := fs.Bool("debug", false, "trace checks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	plat := newPlatform()
	tcfg := tunnelConfig{ClientIP: defaultClientIP, Split: splitEnabled()}
	if plat.TunnelConfigured() {
		tcfg.PrivateKey = "configured"
	}
	return verifyAll(plat, tcfg, true)
}

func cmdDiagnose(args []string) error {
	fs := newFlagSet("diagnose")
	debug := fs.Bool("debug", false, "also enable tracing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	return diagnose()
}

func cmdPubkey(args []string) error {
	fs := newFlagSet("pubkey")
	key := fs.String("key", "", "private key")
	keyFile := fs.String("key-file", "", "file containing the private key")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	private, err := resolveKey(*key, *keyFile)
	if err != nil {
		return err
	}
	pub, err := publicKey(private)
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

func cmdDisable(args []string) error {
	fs := newFlagSet("disable")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	plat := newPlatform()
	if err := plat.RequirePrivilege(); err != nil {
		return err
	}
	if err := plat.Disable(); err != nil {
		return err
	}
	fmt.Println("egress disabled; DNS and routing are back to the system defaults")
	return nil
}

func cmdEnable(args []string) error {
	fs := newFlagSet("enable")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	plat := newPlatform()
	if err := plat.RequirePrivilege(); err != nil {
		return err
	}
	if err := plat.Enable(); err != nil {
		return err
	}
	// Enable only restarts the service. Split mode also needs its per-user
	// proxy and PAC back, which disable removed, and the update check, which
	// disable deletes.
	if runtime.GOOS == "windows" && splitEnabled() {
		if err := configureWindowsSplit(); err != nil {
			return fmt.Errorf("split client setup: %w", err)
		}
	}
	if err := installUpdateTimer(updatePollInterval); err != nil {
		fmt.Fprintf(os.Stderr, "warning: update timer not installed: %v\n", err)
	}
	fmt.Println("egress enabled")
	return nil
}

func cmdRemove(args []string) error {
	fs := newFlagSet("remove")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))

	plat := newPlatform()
	if err := plat.RequirePrivilege(); err != nil {
		return err
	}
	if err := plat.Remove(); err != nil {
		return err
	}
	fmt.Println("egress removed")
	return nil
}

// installedBinaryPath is the canonical name under installDir. install copies
// the running binary there, and the boot service and Remove use it.
func installedBinaryPath() string {
	name := "egress"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(installDir(), name)
}

// ensureInstalledBinary copies the running executable to the canonical install
// path when it was started from anywhere else (Downloads, USB stick, /tmp),
// and returns the canonical path. The boot service and the scheduled task
// always reference the canonical path, so installs from a temporary location
// survive reboots. Reinstalls overwrite the previous copy; the old supervisor
// is already stopped by the time install calls this.
func ensureInstalledBinary() (string, error) {
	dest := installedBinaryPath()
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}
	if filepath.Clean(self) == filepath.Clean(dest) {
		return dest, nil
	}
	if a, errA := os.Stat(self); errA == nil {
		if b, errB := os.Stat(dest); errB == nil && os.SameFile(a, b) {
			return dest, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return "", err
	}
	src, err := os.Open(self)
	if err != nil {
		return "", fmt.Errorf("read the running binary: %w", err)
	}
	defer src.Close()
	tmp := dest + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("copy to %s: %w", dest, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", closeErr
	}
	// Windows refuses to replace an image that is still mapped; the old
	// supervisor was stopped earlier, but its process may need a moment.
	var renameErr error
	for attempt := 0; attempt < 20; attempt++ {
		if renameErr = os.Rename(tmp, dest); renameErr == nil {
			debugf("installed binary to %s", dest)
			return dest, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return "", fmt.Errorf("replace %s: %w", dest, renameErr)
}

// removeInstalledBinary deletes the canonical install path unless that is the
// executable currently running, which cannot be unlinked on Windows and should
// not vanish underneath the user on Linux.
func removeInstalledBinary() {
	dest := installedBinaryPath()
	self, err := os.Executable()
	if err == nil {
		if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
			self = resolved
		}
		if filepath.Clean(self) == filepath.Clean(dest) {
			fmt.Printf("the running binary is %s; delete it after this command exits\n", dest)
			return
		}
		if a, errA := os.Stat(self); errA == nil {
			if b, errB := os.Stat(dest); errB == nil && os.SameFile(a, b) {
				fmt.Printf("the running binary is %s; delete it after this command exits\n", dest)
				return
			}
		}
	}
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		fmt.Printf("could not delete %s: %v\n", dest, err)
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
