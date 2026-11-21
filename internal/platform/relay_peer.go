package platform

import "strings"

func hasPeer(conf, pubkey string) bool {
	_, peers := splitPeerBlocks(conf)
	for _, block := range peers {
		if peerPublicKey(block) == pubkey {
			return true
		}
	}
	return false
}

func renderRelayPeer(conf, pubkey, endpoint string, allowed []string) (string, bool) {
	prelude, peers := splitPeerBlocks(conf)
	// A passive peer carries no routes and no endpoint: it exists only so an
	// inbound handshake from the other side is accepted and its address learned.
	exitBlock := "[Peer]\nPublicKey = " + pubkey
	if len(allowed) > 0 {
		exitBlock += "\nAllowedIPs = " + strings.Join(allowed, ",")
	}
	if endpoint != "" {
		exitBlock += "\nEndpoint = " + endpoint + "\nPersistentKeepalive = 25"
	}
	var out []string
	if strings.TrimSpace(prelude) != "" {
		out = append(out, strings.TrimRight(prelude, "\n"))
	}
	for _, block := range peers {
		if peerPublicKey(block) == pubkey {
			out = append(out, exitBlock)
			continue
		}
		out = append(out, strings.TrimRight(block, "\n"))
	}
	if !hasPeer(conf, pubkey) {
		out = append(out, exitBlock)
	}
	updated := strings.Join(out, "\n\n") + "\n"
	return updated, updated != conf
}

func removePeerBlock(conf, pubkey string) (string, bool) {
	prelude, peers := splitPeerBlocks(conf)
	var out []string
	if strings.TrimSpace(prelude) != "" {
		out = append(out, strings.TrimRight(prelude, "\n"))
	}
	changed := false
	for _, block := range peers {
		if peerPublicKey(block) == pubkey {
			changed = true
			continue
		}
		out = append(out, strings.TrimRight(block, "\n"))
	}
	if !changed {
		return conf, false
	}
	return strings.Join(out, "\n\n") + "\n", true
}

func splitPeerBlocks(conf string) (string, []string) {
	var prelude, peers, cur []string
	inPeer := false
	for _, line := range strings.Split(conf, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "[Peer]") {
			if inPeer && len(cur) > 0 {
				peers = append(peers, strings.Join(cur, "\n"))
			}
			cur = []string{line}
			inPeer = true
			continue
		}
		if inPeer {
			cur = append(cur, line)
		} else {
			prelude = append(prelude, line)
		}
	}
	if inPeer && len(cur) > 0 {
		peers = append(peers, strings.Join(cur, "\n"))
	}
	return strings.Join(prelude, "\n"), peers
}

func peerPublicKey(block string) string {
	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "PublicKey") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// peerAllowedIPs returns the AllowedIPs currently written for a peer.
func peerAllowedIPs(conf, pubkey string) map[string]bool {
	_, peers := splitPeerBlocks(conf)
	out := map[string]bool{}
	for _, block := range peers {
		if peerPublicKey(block) != pubkey {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "AllowedIPs") {
				continue
			}
			for _, p := range strings.Split(value, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out[p] = true
				}
			}
		}
		return out
	}
	return out
}

// allowedAdds reports whether after contains an address the peer did not
// already permit. Additions must reload the Windows tunnel so its inbound
// filters include them; removals do not.
func allowedAdds(before map[string]bool, after []string) bool {
	for _, p := range after {
		p = strings.TrimSpace(p)
		if p != "" && !before[p] {
			return true
		}
	}
	return false
}
