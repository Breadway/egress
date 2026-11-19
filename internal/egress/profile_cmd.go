package egress

import (
	"errors"
	"fmt"

	"egress/internal/profile"
	"egress/internal/update"
)

// cmdProfile signs and verifies device profiles. Signing happens offline with
// the update key; the client binary verifies with the public half compiled in,
// so a profile is trusted regardless of how it was delivered.
func cmdProfile(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: egress profile sign|verify [flags]")
	}
	switch args[0] {
	case "sign":
		fs := newFlagSet("profile sign")
		keyFile := fs.String("key-file", "", "Ed25519 signing key")
		in := fs.String("in", "", "profile to sign (omit to start a new one)")
		out := fs.String("out", "", "where to write the signed profile")
		name := fs.String("name", "", "profile name when starting a new one")
		relayUser := fs.String("relay-user", "", "relay user for a new profile")
		relayPass := fs.String("relay-pass", "", "relay password for a new profile")
		fallbacks := fs.String("doh-fallbacks", "", "fallback resolvers as host=ip,...")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *keyFile == "" || *out == "" {
			return errors.New("usage: egress profile sign --key-file K --out FILE [--in FILE | --name N --relay-user U --relay-pass P]")
		}
		key, err := update.LoadSigningKey(*keyFile)
		if err != nil {
			return err
		}
		var p profile.Profile
		if *in != "" {
			if p, err = profile.Load(*in); err != nil {
				return err
			}
		} else {
			if *name == "" {
				return errors.New("a new profile needs --name")
			}
			p = profile.New(*name)
			p.Relay = profile.Relay{User: *relayUser, Pass: *relayPass}
		}
		if *fallbacks != "" {
			p.DoH.Fallbacks = *fallbacks
		}
		signed, err := profile.Sign(p, key)
		if err != nil {
			return err
		}
		if err := profile.Save(*out, signed); err != nil {
			return err
		}
		fmt.Printf("signed profile for %q written to %s\n", p.Name, *out)
		return nil

	case "verify":
		fs := newFlagSet("profile verify")
		in := fs.String("in", "", "profile to verify")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *in == "" {
			return errors.New("usage: egress profile verify --in FILE")
		}
		p, err := profile.Load(*in)
		if err != nil {
			return err
		}
		pub, err := update.PublicKeyBytes()
		if err != nil {
			return err
		}
		if err := profile.Verify(p, pub); err != nil {
			return err
		}
		fmt.Printf("profile %q verified\n", p.Name)
		fmt.Printf("  created:  %s\n", p.Created)
		fmt.Printf("  relay:    %s\n", p.Relay.User)
		fmt.Printf("  doh fallbacks: %s\n", p.DoH.Fallbacks)
		return nil
	}
	return fmt.Errorf("unknown profile command %q", args[0])
}
