package server_inventory

import "testing"

func TestStaticInventoryDefaultsToSSH(t *testing.T) {
	inventory, err := NewStatic(`{
		"host-1": {
			"address": "server.example:22",
			"username": "ubuntu",
			"credentialSecretId": "secret/host-1",
			"hostPublicKey": "ssh-ed25519 AAAATEST"
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	server, err := inventory.Get(t.Context(), "host-1")
	if err != nil {
		t.Fatal(err)
	}
	if server.HostID != "host-1" || server.ConnectionType != "ssh" {
		t.Fatalf("server = %#v", server)
	}
}
