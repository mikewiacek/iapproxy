//go:build windows

package main

import "context"

func setupSignalHandlers(ctx context.Context, cancel context.CancelFunc, tunnel *Tunnel) {
    // Windows doesn’t support SIGUSR1, so just handle shutdown.
    go func() {
        <-ctx.Done()
    }()
}

