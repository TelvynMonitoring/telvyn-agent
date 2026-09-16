//go:build !linux

package clock

import "context"

// OffsetSeconds is unavailable on non-Linux hosts; the backend still records
// the effective backend-versus-agent clock offset from the heartbeat.
func OffsetSeconds(_ context.Context) (float64, bool) {
	return 0, false
}
