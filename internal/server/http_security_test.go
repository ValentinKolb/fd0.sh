package server

import "testing"

func TestServerHTTPClientsRejectRedirects(t *testing.T) {
	if peerHTTPClient.CheckRedirect == nil {
		t.Fatal("peer resolver HTTP client follows redirects")
	}
	if newReplicationHTTPClient().CheckRedirect == nil {
		t.Fatal("replication HTTP client follows redirects")
	}
}
