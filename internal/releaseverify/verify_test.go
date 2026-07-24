package releaseverify

import "testing"

func TestRejectsMissingBundleBeforeTrustLookup(t *testing.T) {
	err := Verify("/does/not/exist.sigstore.json", "/does/not/exist.txt", "invalid")
	if err == nil {
		t.Fatal("Verify accepted a missing bundle")
	}
}
