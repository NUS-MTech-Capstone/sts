package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/NUS-MTech-Capstone/sts/internal/change_request"
	"github.com/NUS-MTech-Capstone/sts/internal/config"
	"github.com/NUS-MTech-Capstone/sts/internal/httpapi"
	"github.com/NUS-MTech-Capstone/sts/internal/observability"
	"github.com/NUS-MTech-Capstone/sts/internal/server_inventory"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
	"github.com/NUS-MTech-Capstone/sts/internal/workload"
)

func main() {
	observability.ConfigureLogger("sts")
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("config validation failed", "error", err)
		os.Exit(1)
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
			slog.Error("static server inventory failed", "error", err)
			os.Exit(1)
		}
		serverInventory = staticInventory
	}
	workloadValidator, err := workload.New(
		cfg.KubernetesAPIURL, cfg.KubernetesTokenFile, cfg.KubernetesCAFile,
		cfg.AutomationAudience, cfg.AutomationNamespace, cfg.AutomationServiceAccount,
		cfg.UpstreamClientTimeout,
	)
	if err != nil {
		slog.Warn("automation workload validation disabled", "error", err)
	}

	addr := ":" + cfg.Port
	slog.Info("server_listening", "addr", addr)
	tokenConfig := service.TokenConfig{
		TTL:           cfg.TokenTTL,
		AutomationTTL: cfg.AutomationTokenTTL,
		SigningKey:    []byte(cfg.JWTSigningKey),
		Issuer:        cfg.JWTIssuer,
		Audience:      cfg.JWTAudience,
		ClockSkew:     cfg.JWTClockSkew,
	}
	svc := service.New(tokenConfig, changeRequests, serverInventory)
	if workloadValidator != nil {
		svc = service.New(tokenConfig, changeRequests, serverInventory, workloadValidator)
	}
	if err := http.ListenAndServe(
		addr,
		httpapi.New(svc),
	); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
