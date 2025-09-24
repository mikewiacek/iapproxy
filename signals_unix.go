//go:build !windows

package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
)

func setupSignalHandlers(ctx context.Context, cancel context.CancelFunc, tunnel *Tunnel) {
    sigChan := make(chan os.Signal, 1)
    statsChan := make(chan os.Signal, 1)

    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    signal.Notify(statsChan, syscall.SIGUSR1)

    go func() {
        <-sigChan
        log.Println("Received shutdown signal")
        cancel()
    }()

    go func() {
        for {
            <-statsChan
            tunnel.DumpStats()
        }
    }()
}

