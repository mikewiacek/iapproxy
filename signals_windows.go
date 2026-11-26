//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
)

func setupSignalHandlers(ctx context.Context, cancel context.CancelFunc, tunnel *Tunnel) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	go func() {
		defer signal.Stop(sigChan)
		select {
		case <-ctx.Done():
		case <-sigChan:
			log.Println("Received shutdown signal")
			cancel()
		}
	}()
}
