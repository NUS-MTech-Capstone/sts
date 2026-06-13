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
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	var changeRequests service.ChangeRequestClient
	if cfg.ChangeRequestURL != "" {
		changeRequests = change_request.New(cfg.ChangeRequestURL, cfg.UpstreamClientTimeout)
	}
	var serverInventory service.ServerInventoryClient
	if cfg.ServerInventoryURL != "" {
		serverInventory = server_inventory.New(cfg.ServerInventoryURL, cfg.UpstreamClientTimeout)
	} else if cfg.ServerInventoryStaticJSON != "" {
		staticInventory, err := server_inventory.NewStatic(cfg.ServerInventoryStaticJSON)
		if err != nil {
			log.Fatal(err)
		}
		serverInventory = staticInventory
	}

	addr := ":" + cfg.Port
	log.Printf("sts listening on %s", addr)
	log.Fatal(http.ListenAndServe(
		addr,
		httpapi.New(service.New(
			service.TokenConfig{
				TTL:        cfg.TokenTTL,
				SigningKey: []byte(cfg.JWTSigningKey),
				Issuer:     cfg.JWTIssuer,
				Audience:   cfg.JWTAudience,
				ClockSkew:  cfg.JWTClockSkew,
			},
			changeRequests,
			serverInventory,
		)),
	))
}
