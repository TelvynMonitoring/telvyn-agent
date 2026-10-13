package telvyn

import (
	"context"
	"log"
	"time"
)

// Bootstrap is used by the compile-time integration. The application's main
// retains ownership of signals and server draining; normal return flushes spans.
func Bootstrap() func() {
	shutdown, err := Start(context.Background())
	if err != nil {
		log.Printf("Telvyn agent initialization failed: %v", err)
		return func() {}
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			log.Printf("Telvyn agent flush failed: %v", err)
		}
	}
}
