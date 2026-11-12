package platform

import "io"

// section and show are the diagnose renderers; they talk to commands, so they
// live with the platform rather than with the CLI.
func section(w io.Writer, name string) {
	_, _ = io.WriteString(w, "\n== "+name+" ==\n")
}

func show(w io.Writer, name string, args ...string) {
	_, _ = io.WriteString(w, "$ "+name)
	for _, a := range args {
		_, _ = io.WriteString(w, " "+a)
	}
	_, _ = io.WriteString(w, "\n")
}
