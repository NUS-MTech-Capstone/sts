SERVICE := sts
IMAGE ?= dendenmushi/$(SERVICE):local
PORT ?= 8082
CHANGE_REQUEST_URL ?=
SERVER_INVENTORY_URL ?=
GOCACHE ?= /private/tmp/ddm-go-build-cache
GOMODCACHE ?= /private/tmp/ddm-go-mod-cache

.PHONY: run test build docker-build clean

run:
	PORT=$(PORT) CHANGE_REQUEST_URL=$(CHANGE_REQUEST_URL) SERVER_INVENTORY_URL=$(SERVER_INVENTORY_URL) go run ./cmd/server

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/$(SERVICE) ./cmd/server

docker-build:
	docker build -t $(IMAGE) .

clean:
	rm -rf bin
