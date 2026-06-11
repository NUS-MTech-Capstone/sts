package main

import (
	"log"
	"net/http"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/config"
	"github.com/NUS-MTech-Capstone/sts/internal/httpapi"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

func main() {
	cfg := config.Load()
	var changeRequests service.ChangeRequestClient
	if cfg.ChangeRequestURL != "" {
		changeRequests = change_request.New(cfg.ChangeRequestURL, cfg.UpstreamClientTimeout)
	}
	var serverInventory service.ServerInventoryClient
	if cfg.ServerInventoryURL != "" {
		serverInventory = server_inventory.New(cfg.ServerInventoryURL, cfg.UpstreamClientTimeout)
	}

	addr := ":" + cfg.Port
	log.Printf("sts listening on %s", addr)
	log.Fatal(http.ListenAndServe(
		addr,
		httpapi.New(service.New(cfg.TokenTTL, changeRequests, serverInventory)),
	))
}
