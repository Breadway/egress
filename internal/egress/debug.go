package egress

import (
	"log"
	"os"

	"egress/internal/health"
	"egress/internal/logx"
)

func appLogger() *log.Logger { return logx.Logger() }

func closeLog() { logx.Close() }

func setupLogging(debug bool) { logx.Setup(debug, logPath()) }

func debugf(format string, args ...any) { logx.Debugf(format, args...) }

func truncate(s string, max int) string { return logx.Truncate(s, max) }

func execLogged(name string, args ...string) ([]byte, error) { return logx.ExecLogged(name, args...) }

func runLogged(name string, args ...string) error { return logx.RunLogged(name, args...) }

// diagnose and every helper below live in internal/health; the CLI only needs
// the entry point.
func diagnose() error {
	return health.WriteDiagnose(os.Stdout)
}
