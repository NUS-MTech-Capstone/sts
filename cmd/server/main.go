package main

import (
	"log"
	"net/http"

	"github.com/NUS-MTech-Capstone/sts/internal/config"
	"github.com/NUS-MTech-Capstone/sts/internal/httpapi"
	"github.com/NUS-MTech-Capstone/sts/internal/service"
)

func main() {
	cfg := config.Load()
	addr := ":" + cfg.Port
	log.Printf("sts listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, httpapi.New(service.New(cfg.TokenTTL))))
}
