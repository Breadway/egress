package main

import (
	_ "embed"
	"net/http"
)

// The Bread design system specifies Varela Round. Serving it from the app
// keeps the UI consistent even when the visitor's network blocks font CDNs.

//go:embed assets/varela-round.ttf
var varelaRound []byte

func (s *server) fontAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "font/ttf")
	w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
	_, _ = w.Write(varelaRound)
}
