// Command updateserver serves signed egress releases to tunnel members only.
// It has no signing key and no database: the directory it serves is written by
// the offline publisher.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	archRe = regexp.MustCompile(`^[a-z0-9]+$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func main() {
	listen := flag.String("listen", "10.88.0.1:7107", "tunnel-side listen address")
	dir := flag.String("dir", "/var/lib/egress-updates", "directory of manifests and blobs")
	flag.Parse()

	s := &server{dir: *dir}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
	}
	log.Printf("updateserver: serving %s on %s", *dir, *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	dir string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch {
	case r.URL.Path == "/healthz":
		_, _ = w.Write([]byte("ok\n"))
	case r.URL.Path == "/manifest":
		s.serveManifest(w, r)
	case strings.HasPrefix(r.URL.Path, "/blob/"):
		s.serveBlob(w, strings.TrimPrefix(r.URL.Path, "/blob/"))
	default:
		http.NotFound(w, r)
	}
}

func (s *server) serveManifest(w http.ResponseWriter, r *http.Request) {
	goos := r.URL.Query().Get("os")
	goarch := r.URL.Query().Get("arch")
	if !archRe.MatchString(goos) || !archRe.MatchString(goarch) {
		http.Error(w, "bad os or arch", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.dir, "manifests", goos+"-"+goarch+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "no release for this target", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *server) serveBlob(w http.ResponseWriter, sum string) {
	if !shaRe.MatchString(sum) {
		http.Error(w, "bad blob id", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.dir, "blobs", sum)
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, &http.Request{Method: http.MethodGet}, "", info.ModTime(), f)
}
