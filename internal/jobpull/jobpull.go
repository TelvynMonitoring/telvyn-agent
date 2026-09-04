// Package jobpull consumes short-lived device automation jobs over authenticated HTTP.
package jobpull

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ispwatch/collector/internal/tools"
)

type Config struct {
	Endpoint        string
	TenantID        string
	CollectorID     string
	PollInterval    time.Duration
	LongPollSeconds int
	HTTPClient      *http.Client
	Logger          *slog.Logger
}

type pullResponse struct {
	Jobs []job `json:"jobs"`
}

type job struct {
	ID             string `json:"id"`
	Attempt        int    `json:"attempt"`
	Host           string `json:"host"`
	Vendor         string `json:"vendor"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	SSHPort        int    `json:"ssh_port"`
	SSHUser        string `json:"ssh_user"`
	SecretKind     string `json:"secret_kind"`
	Secret         string `json:"secret"`
	KnownHost      string `json:"known_host"`
	TestOnly       bool   `json:"test_only"`
}

// Run waits for one job at a time. The server holds the request during the
// long-poll window; a result remains in memory and is retried until acknowledged.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Endpoint == "" || cfg.TenantID == "" || cfg.CollectorID == "" || cfg.HTTPClient == nil {
		return fmt.Errorf("jobpull: incomplete config")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if cfg.LongPollSeconds <= 0 {
		cfg.LongPollSeconds = 25
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "jobpull")

	var pending *completed
	retryDelay := 2 * time.Second
	for {
		if pending != nil {
			if err := postResult(ctx, cfg, *pending); err != nil {
				log.Warn("result not acknowledged; will retry", "job_id", pending.id, "err", err)
				if err := waitContext(ctx, retryDelay); err != nil {
					return nil
				}
			} else {
				pending = nil
				retryDelay = 2 * time.Second
			}
		} else {
			j, longPollResponse, err := pullOnce(ctx, cfg)
			if err != nil {
				log.Warn("job pull failed", "err", err)
				if err := waitContext(ctx, retryDelay); err != nil {
					return nil
				}
				if retryDelay < 30*time.Second {
					retryDelay *= 2
					if retryDelay > 30*time.Second {
						retryDelay = 30 * time.Second
					}
				}
			} else if j != nil {
				retryDelay = 2 * time.Second
				result := execute(ctx, *j)
				pending = &completed{id: j.ID, result: result}
			} else if !longPollResponse {
				// Compatibilidade com backend antigo, que responde 200 vazio
				// imediatamente e não entende wait_seconds.
				if err := waitContext(ctx, cfg.PollInterval); err != nil {
					return nil
				}
			}
		}
	}
}

func pullOnce(ctx context.Context, cfg Config) (*job, bool, error) {
	query := url.Values{}
	query.Set("tenant_id", cfg.TenantID)
	query.Set("collector_id", cfg.CollectorID)
	query.Set("wait_seconds", strconv.Itoa(cfg.LongPollSeconds))
	u := fmt.Sprintf("%s/api/collector/v1/jobs?%s", cfg.Endpoint, query.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, true, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}
	var out pullResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, false, err
	}
	if len(out.Jobs) == 0 {
		return nil, false, nil
	}
	return &out.Jobs[0], false, nil
}

func waitContext(ctx context.Context, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func execute(ctx context.Context, j job) map[string]any {
	if !j.TestOnly {
		if err := tools.ValidateReadOnlySSHCommand(j.Vendor, j.Command); err != nil {
			return map[string]any{"success": false, "exit_code": -1, "error": err.Error()}
		}
	}
	args := map[string]any{
		"host": j.Host, "port": j.SSHPort, "user": j.SSHUser,
		"timeout": j.TimeoutSeconds,
	}
	if !j.TestOnly {
		args["command"] = j.Command
	}
	if j.KnownHost != "" {
		args["known_host"] = j.KnownHost
	}
	if j.SecretKind == "private_key" {
		args["private_key"] = j.Secret
	} else {
		args["password"] = j.Secret
	}
	var result map[string]any
	var err error
	if j.TestOnly {
		result, err = (tools.SSHExec{}).TestConnection(ctx, args)
	} else {
		result, err = (tools.SSHExec{}).Execute(ctx, args)
	}
	if err != nil {
		return map[string]any{"success": false, "exit_code": -1, "error": err.Error()}
	}
	if j.TestOnly {
		return result
	}
	exit, _ := result["exit_code"].(float64)
	errText, _ := result["error"].(string)
	result["success"] = exit == 0 && errText == ""
	return result
}

type completed struct {
	id     string
	result map[string]any
}

func postResult(ctx context.Context, cfg Config, done completed) error {
	body, err := json.Marshal(done.result)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/api/collector/v1/jobs/%s/result?tenant_id=%s&collector_id=%s",
		cfg.Endpoint, url.PathEscape(done.id), url.QueryEscape(cfg.TenantID), url.QueryEscape(cfg.CollectorID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, msg)
	}
	return nil
}
