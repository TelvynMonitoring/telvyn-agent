package checks

import (
	"context"
	"github.com/ispwatch/collector/internal/clock"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/shirou/gopsutil/v4/common"
	"google.golang.org/protobuf/types/known/timestamppb"
	"log/slog"
	"path/filepath"
	"time"
)

// Context-local host paths leave the agent's own process metrics untouched.
func StartNodeSystem(ctx context.Context, log *slog.Logger, out chan<- []*collectorv1.Metric, hostID, procRoot string, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	root := filepath.Join(procRoot, "1/root")
	hostCtx := context.WithValue(ctx, common.EnvKey, common.EnvMap{
		common.HostProcEnvKey: procRoot,
		common.HostSysEnvKey:  filepath.Join(filepath.Dir(procRoot), "sys"),
		common.HostRootEnvKey: root,
	})
	check := &linuxSystemCheck{hostID: hostID, root: root, networkProc: filepath.Join(procRoot, "1")}
	// NTP uses a separate interval so an unreachable time server does not delay
	// CPU, memory and disk collection. The public pool permits 15-minute polling.
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			if offset, ok := clock.OffsetSeconds(ctx); ok {
				metric := &collectorv1.Metric{HostId: hostID, MetricName: "ntp.offset", Value: offset,
					Time:   timestamppb.New(time.Now().Add(time.Duration(offset * float64(time.Second)))),
					Source: "ntp"}
				select {
				case out <- []*collectorv1.Metric{metric}:
				case <-ctx.Done():
					return
				}
			} else {
				log.Warn("node NTP offset unavailable")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			metrics, err := check.Run(hostCtx)
			if offset, ok := clock.IntakeOffsetSeconds(time.Now()); ok {
				metrics = append(metrics, &collectorv1.Metric{HostId: hostID, MetricName: "ntp.intake_offset",
					Value: offset, Time: timestamppb.New(time.Now().Add(time.Duration(offset * float64(time.Second)))), Source: "ntp"})
			}
			if err != nil {
				log.Warn("node system collection failed", "error", err)
			}
			if len(metrics) > 0 {
				select {
				case out <- metrics:
				case <-ctx.Done():
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
