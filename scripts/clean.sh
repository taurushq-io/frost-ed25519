#!/usr/bin/env bash

go vet ./...

find . -name "*\.go" -exec goimports -w {} \;

golangci-lint run