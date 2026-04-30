package cli

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// SafetyNumber implements PROTOCOL.md §2.4. Two parties compare these
// numbers out-of-band to confirm they hold the same identity card.
//
//	digest = SHA-256("fd0-safety-v1" || cbor({shortId, super_pub}))
//	take first 24 bytes
//	encode as 12 groups of 5 decimal digits (16 bits per group)
//	display as 3 lines of 4 groups
func SafetyNumber(shortID string, superPub []byte) (string, error) {
	body, err := proto.Marshal(struct {
		ShortID  string `cbor:"shortId"`
		SuperPub []byte `cbor:"super_pub"`
	}{shortID, superPub})
	if err != nil {
		return "", err
	}
	in := append([]byte(proto.DomainSafety), body...)
	sum := sha256.Sum256(in)
	if len(sum) < 24 {
		return "", fmt.Errorf("safety: digest too short")
	}
	groups := make([]string, 12)
	for i := 0; i < 12; i++ {
		v := uint16(sum[i*2])<<8 | uint16(sum[i*2+1])
		groups[i] = fmt.Sprintf("%05d", v)
	}
	var lines []string
	for i := 0; i < 12; i += 4 {
		lines = append(lines, strings.Join(groups[i:i+4], " "))
	}
	return strings.Join(lines, "\n"), nil
}
