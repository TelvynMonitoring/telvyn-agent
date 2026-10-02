package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

var externalMetricName = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
var externalResourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
var externalLabel = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

var externalUnits = map[string]bool{
	"boolean": true, "fraction": true, "percent": true,
	"byte": true, "byte_per_second": true, "second": true, "count": true,
}

var externalLabels = map[string]bool{
	"provider": true, "resource_type": true, "instance_id": true,
	"node": true, "cluster": true, "datastore": true, "power_state": true,
}

// ExternalInventory is validated but deliberately not sent to the backend.
type ExternalInventory struct {
	ResourceID string `json:"resource_id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	State      string `json:"state"`
	ParentID   string `json:"parent_id"`
	ObservedAt string `json:"observed_at"`
}

type externalMetric struct {
	Name       string            `json:"name"`
	Value      *float64          `json:"value"`
	Type       string            `json:"type"`
	Unit       string            `json:"unit"`
	Timestamp  string            `json:"timestamp"`
	ResourceID string            `json:"resource_id"`
	Tags       map[string]string `json:"tags"`
}

type externalResponse struct {
	ProtocolVersion int                 `json:"protocol_version"`
	Metrics         []externalMetric    `json:"metrics"`
	Inventory       []ExternalInventory `json:"inventory"`
	Status          string              `json:"status"`
	Coverage        json.RawMessage     `json:"coverage"`
	Error           string              `json:"error"`
}

func mapExternalResponse(raw []byte, instanceID, hostID, check string, coreTags map[string]string) ([]*collectorv1.Metric, []ExternalInventory, json.RawMessage, string, error) {
	if len(raw) == 0 || len(raw) > externalOutputLimit {
		return nil, nil, nil, "", errors.New("external.python: empty or oversized response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response externalResponse
	if err := decoder.Decode(&response); err != nil {
		return nil, nil, nil, "", errors.New("external.python: invalid response JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, nil, "", errors.New("external.python: trailing response data")
	}
	if response.ProtocolVersion != 1 || (response.Status != "ok" && response.Status != "partial" && response.Status != "error") {
		return nil, nil, nil, "", errors.New("external.python: invalid protocol or status")
	}
	if response.Status == "error" {
		return nil, nil, nil, "", errors.New("external.python: check reported failure")
	}
	if len(response.Metrics) > 500 || len(response.Inventory) > 1000 || len(response.Coverage) > 8192 {
		return nil, nil, nil, "", errors.New("external.python: result limit exceeded")
	}
	coverage := map[string]json.RawMessage{}
	if len(response.Coverage) != 0 && string(response.Coverage) != "null" {
		if err := json.Unmarshal(response.Coverage, &coverage); err != nil || coverage == nil || len(coverage) > 32 {
			return nil, nil, nil, "", errors.New("external.python: invalid coverage")
		}
	}
	for _, item := range response.Inventory {
		if !externalResourceID.MatchString(item.ResourceID) || !externalLabel.MatchString(item.Type) ||
			!validText(item.Name, 256) || !validText(item.State, 64) ||
			(item.ParentID != "" && !externalResourceID.MatchString(item.ParentID)) {
			return nil, nil, nil, "", errors.New("external.python: invalid inventory")
		}
		if _, err := externalTime(item.ObservedAt); err != nil {
			return nil, nil, nil, "", errors.New("external.python: invalid inventory timestamp")
		}
	}
	metrics := make([]*collectorv1.Metric, 0, len(response.Metrics))
	skippedCounts := 0
	for _, item := range response.Metrics {
		if !externalMetricName.MatchString(item.Name) || !strings.HasPrefix(item.Name, "telvyn."+check+".") ||
			item.Value == nil || math.IsNaN(*item.Value) || math.IsInf(*item.Value, 0) ||
			!externalUnits[item.Unit] || !externalResourceID.MatchString(item.ResourceID) {
			return nil, nil, nil, "", errors.New("external.python: invalid metric")
		}
		at, err := externalTime(item.Timestamp)
		if err != nil {
			return nil, nil, nil, "", errors.New("external.python: invalid metric timestamp")
		}
		if item.Type == "count" { // Current PostMetrics encodes Gauge, not OTLP Sum.
			skippedCounts++
			continue
		}
		if item.Type != "gauge" {
			return nil, nil, nil, "", errors.New("external.python: unsupported metric type")
		}
		if len(item.Tags) > 16 {
			return nil, nil, nil, "", errors.New("external.python: too many labels")
		}
		tags := make(map[string]string, len(coreTags)+len(item.Tags)+3)
		for key, value := range coreTags {
			tags[key] = value
		}
		for key, value := range item.Tags {
			if !externalLabel.MatchString(key) || !validText(value, 128) {
				return nil, nil, nil, "", errors.New("external.python: invalid label")
			}
			if fixed, ok := coreTags[key]; ok {
				if fixed != value {
					return nil, nil, nil, "", errors.New("external.python: core label override")
				}
				continue
			}
			if !externalLabels[key] || key == "instance_id" && value != instanceID || key == "provider" && value != check {
				return nil, nil, nil, "", errors.New("external.python: unapproved label")
			}
			tags[key] = value
		}
		tags["instance_id"] = instanceID
		tags["external_resource_id"] = item.ResourceID
		tags["unit"] = item.Unit
		metrics = append(metrics, &collectorv1.Metric{
			Time: timestamppb.New(at), HostId: hostID, MetricName: item.Name,
			Value: *item.Value, Tags: tags, Source: "external.python",
		})
	}
	if skippedCounts > 0 {
		coverage["unsupported_count_metrics"], _ = json.Marshal(skippedCounts)
		response.Status = "partial"
	}
	coverageBytes, err := json.Marshal(coverage)
	if err != nil || len(coverageBytes) > 8192 {
		return nil, nil, nil, "", fmt.Errorf("external.python: coverage limit exceeded")
	}
	return metrics, response.Inventory, coverageBytes, response.Status, nil
}

func externalTime(value string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || at.Before(time.Now().Add(-24*time.Hour)) || at.After(time.Now().Add(5*time.Minute)) {
		return time.Time{}, errors.New("timestamp outside permitted window")
	}
	return at, nil
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}
