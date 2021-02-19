#!/usr/bin/env bash

go test --race ./pkg/...
go run ./test