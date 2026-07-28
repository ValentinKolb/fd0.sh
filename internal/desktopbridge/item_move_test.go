package desktopbridge

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

func TestMoveItemKind(t *testing.T) {
	tests := []struct {
		recordType string
		recordName string
		wantKind   cli.ItemKind
		wantName   string
	}{
		{"kv.string", "TOKEN", cli.KindSecret, "TOKEN"},
		{passitem.TypePassItem, "pass:GitHub", cli.KindPass, "GitHub"},
		{sshhost.TypeHost, "host:server", cli.KindHost, "server"},
		{string(sshkey.TypeEd25519), "ssh:deploy", cli.KindKey, "deploy"},
		{kubeconfig.TypeKubeconfig, "kube:prod", cli.KindKube, "prod"},
		{talosctx.TypeTalosContext, "talos:home", cli.KindTalos, "home"},
	}
	for _, test := range tests {
		t.Run(test.recordName, func(t *testing.T) {
			kind, name, err := moveItemKind(test.recordType, test.recordName)
			if err != nil {
				t.Fatal(err)
			}
			if kind != test.wantKind || name != test.wantName {
				t.Fatalf("moveItemKind(%q, %q) = (%+v, %q), want (%+v, %q)", test.recordType, test.recordName, kind, name, test.wantKind, test.wantName)
			}
		})
	}
}

func TestMoveItemKindRejectsUnknownRecords(t *testing.T) {
	if _, _, err := moveItemKind("custom.record", "custom:item"); err == nil {
		t.Fatal("moveItemKind accepted an unsupported record")
	}
}

func TestMoveItemMethodIsRegistered(t *testing.T) {
	t.Setenv("FD0_HOME", t.TempDir())
	service := &Service{Mode: "system"}
	handshake, err := service.Handle(context.Background(), "bridge.handshake", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := handshake.(HandshakeResult)
	found := false
	for _, capability := range result.Capabilities {
		if capability == "item-move" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("handshake does not advertise item-move: %v", result.Capabilities)
	}

	_, err = service.Handle(context.Background(), "item.move", json.RawMessage(`{
		"source":{"scopeId":"invalid","name":"TOKEN"},
		"targetScopeId":"invalid"
	}`))
	var methodErr *methodError
	if errors.As(err, &methodErr) && methodErr.bridge.Code == "unknown_method" {
		t.Fatal("item.move is not registered in the dispatch switch")
	}
}
