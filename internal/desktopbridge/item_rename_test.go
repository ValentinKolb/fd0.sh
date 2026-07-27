package desktopbridge

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestRenameItemMethodIsRegistered(t *testing.T) {
	t.Setenv("FD0_HOME", t.TempDir())
	service := &Service{Mode: "system"}
	handshake, err := service.Handle(context.Background(), "bridge.handshake", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := handshake.(HandshakeResult)
	found := false
	for _, capability := range result.Capabilities {
		if capability == "item-rename" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("handshake does not advertise item-rename: %v", result.Capabilities)
	}

	_, err = service.Handle(context.Background(), "item.rename", json.RawMessage(`{
		"source":{"scopeId":"invalid","name":"kube:old"},
		"name":"new"
	}`))
	var methodErr *methodError
	if errors.As(err, &methodErr) && methodErr.bridge.Code == "unknown_method" {
		t.Fatal("item.rename is not registered in the dispatch switch")
	}
}
