# GEMS Payload Source Code

This directory contains the source code to generate the binary that serves as
the GEMS Caldera plugin payload. The purpose of this payload is to enable formatting
and sending GEMS protocol messages from the device running the Caldera agent.

The payload is written in Go to version 1.4 of the GEMS specification.
The code has been architected to allow the addition further modules providing
the message formatting for other version of the GEMS specification.

## Building the Payloads

A Makefile is provided to build the payloads for the following architectures:
- Linux x86-64 (GOOS=linux GOARCH=amd64)
- Linux ARM (GOOS=linux GOARCH=arm64)
- Windows (GOOS=windows GOARCH=amd64)
- macOS ARM (GOOS=darwin GOARCH=arm64)

To build for additional architectures, update the Makefile or call `go build`
directly.

## Virtual GEMS Server

The code in `cmd/server` provides a simple GEMS server (or GEMS virtual device)
that can be used to serve as a target for testing the GEMS Caldera plugin or the 
payload binary.
