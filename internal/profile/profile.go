// Package profile carries a device's settings as one signed file, so a machine
// can be provisioned without calling the enrollment server.
//
// The profile is signed with the same offline key as release manifests. A
// recipient verifies it against the public key compiled into the binary, which
// means a profile mailed over any channel is still trustworthy: the signature
// is the trust anchor, not the transport.
package profile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Version is the schema version. Bump on incompatible changes and reject
// unknown versions rather than guessing.
const Version = 1

type Relay struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type DoH struct {
	// Primary is an RFC 8484 URL, empty for the built-in Aegis resolver.
	Primary string `json:"primary,omitempty"`
	// Fallbacks is "host=ip,host=ip", the same form the resolver uses.
	Fallbacks string `json:"fallbacks,omitempty"`
}

type Profile struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Relay   Relay  `json:"relay,omitempty"`
	DoH     DoH    `json:"doh,omitempty"`
	// Exits is reserved for a client-side exit list; the server feed is
	// authoritative today, so it stays empty rather than implying otherwise.
	Exits     []string `json:"exits,omitempty"`
	Signature string   `json:"signature,omitempty"`
}

// payload is the canonical bytes that are signed: the profile with the
// signature cleared, marshalled the same way every time.
func payload(p Profile) ([]byte, error) {
	p.Signature = ""
	return json.Marshal(p)
}

// Sign returns a copy with a valid signature.
func Sign(p Profile, key ed25519.PrivateKey) (Profile, error) {
	if len(key) != ed25519.PrivateKeySize {
		return p, errors.New("bad signing key")
	}
	body, err := payload(p)
	if err != nil {
		return p, err
	}
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))
	return p, nil
}

// Verify checks the signature and the schema version.
func Verify(p Profile, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("bad public key")
	}
	if p.Version != Version {
		return fmt.Errorf("profile schema %d, this build understands %d", p.Version, Version)
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("profile has no usable signature")
	}
	body, err := payload(p)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("profile signature does not verify against this build's key")
	}
	return nil
}

// Load reads and decodes a profile file.
func Load(path string) (Profile, error) {
	var p Profile
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("profile is not valid JSON: %w", err)
	}
	return p, nil
}

// Save writes a profile with a trailing newline, 0600 because it can hold a
// relay password.
func Save(path string, p Profile) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// New builds an unsigned profile with the current timestamp.
func New(name string) Profile {
	return Profile{Version: Version, Name: name, Created: time.Now().UTC().Format(time.RFC3339)}
}
