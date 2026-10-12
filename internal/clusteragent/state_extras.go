package clusteragent

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// Secret bodies are never requested: Table contains metadata/type, not data.
var stateExtraResources = []inventoryResourceSpec{
	{"Endpoints", "/api/v1/endpoints"},
	{"EndpointSlice", "/apis/discovery.k8s.io/v1/endpointslices"},
	{"PersistentVolume", "/api/v1/persistentvolumes"},
	{"PersistentVolumeClaim", "/api/v1/persistentvolumeclaims"},
	{"Ingress", "/apis/networking.k8s.io/v1/ingresses"},
	{"ConfigMap", "/api/v1/configmaps"},
	{"Secret", "/api/v1/secrets"},
}

func (a *Agent) collectStateExtras(ctx context.Context) []*collectorv1.Metric {
	var out []*collectorv1.Metric
	for _, resource := range stateExtraResources {
		var batch []*collectorv1.Metric
		accept := "application/json"
		if resource.kind == "ConfigMap" {
			accept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
		} else if resource.kind == "Secret" {
			accept = "application/json;as=Table;g=meta.k8s.io;v=v1"
		}
		err := a.apiGetPaged(ctx, resource.path, func(body []byte) (string, error) {
			if resource.kind == "Secret" {
				var table struct {
					Kind     string `json:"kind"`
					Metadata struct {
						Continue string `json:"continue"`
					} `json:"metadata"`
					ColumnDefinitions []struct {
						Name string `json:"name"`
					} `json:"columnDefinitions"`
					Rows []struct {
						Cells  []any          `json:"cells"`
						Object map[string]any `json:"object"`
					} `json:"rows"`
				}
				if err := json.Unmarshal(body, &table); err != nil {
					return "", err
				}
				if table.Kind != "Table" {
					return "", fmt.Errorf("Secret metadata response must be Table")
				}
				for _, row := range table.Rows {
					object := map[string]any{"metadata": mapField(row.Object, "metadata")}
					for i, column := range table.ColumnDefinitions {
						if column.Name == "Type" && i < len(row.Cells) {
							object["type"] = row.Cells[i]
						}
					}
					batch = append(batch, a.stateExtraMetrics(resource.kind, object)...)
				}
				return table.Metadata.Continue, nil
			}
			var list resourceList
			if err := json.Unmarshal(body, &list); err != nil {
				return "", err
			}
			if resource.kind == "ConfigMap" {
				var header struct {
					Kind string `json:"kind"`
				}
				if err := json.Unmarshal(body, &header); err != nil {
					return "", err
				}
				if header.Kind != "PartialObjectMetadataList" {
					return "", fmt.Errorf("ConfigMap response must be metadata only")
				}
			}
			for _, raw := range list.Items {
				var object map[string]any
				if err := json.Unmarshal(raw, &object); err != nil {
					return "", err
				}
				batch = append(batch, a.stateExtraMetrics(resource.kind, object)...)
			}
			return list.Metadata.Continue, nil
		}, accept)
		up := 1.0
		if err != nil {
			up = 0
			a.log.Warn("Kubernetes resource collection unavailable", "kind", resource.kind, "error", err)
		} else {
			out = append(out, batch...)
		}
		out = append(out, a.metric("k8s.collection.up", up, map[string]string{"kube_cluster_name": a.cfg.Cluster, "resource_kind": resource.kind}))
	}
	return out
}

func (a *Agent) stateExtraMetrics(kind string, object map[string]any) []*collectorv1.Metric {
	metadata, spec, status := mapField(object, "metadata"), mapField(object, "spec"), mapField(object, "status")
	base := strings.ToLower(kind)
	if kind == "Endpoints" {
		base = "endpoint"
	}
	tags := map[string]string{"kube_cluster_name": a.cfg.Cluster, "kube_namespace": stringField(metadata, "namespace"), "kube_" + base: stringField(metadata, "name")}
	if class := stringField(spec, "storageClassName"); class != "" {
		tags["storageclass"] = class
	}
	var out []*collectorv1.Metric
	emit := func(suffix string, value float64) { out = append(out, a.metric("k8s."+base+"."+suffix, value, tags)) }
	emit("count", 1)
	switch kind {
	case "Secret":
		if value := stringField(object, "type"); value != "" {
			pt := maps.Clone(tags)
			pt["type"] = value
			out = append(out, a.metric("k8s.secret.type", 1, pt))
		}
	case "Endpoints":
		subsets, _ := object["subsets"].([]any)
		for _, item := range subsets {
			subset, _ := item.(map[string]any)
			ports, _ := subset["ports"].([]any)
			if len(ports) == 0 {
				ports = []any{map[string]any{}}
			}
			for _, group := range []string{"addresses", "notReadyAddresses"} {
				addresses, _ := subset[group].([]any)
				for _, item := range addresses {
					address, _ := item.(map[string]any)
					for _, item := range ports {
						port, _ := item.(map[string]any)
						pt := maps.Clone(tags)
						pt["ip"] = stringField(address, "ip")
						pt["port_name"] = stringField(port, "name")
						pt["port_protocol"] = stringField(port, "protocol")
						if number, ok := port["port"].(float64); ok {
							pt["port_number"] = fmt.Sprintf("%.0f", number)
						}
						available, notReady := 1.0, 0.0
						if group == "notReadyAddresses" {
							available, notReady = 0, 1
						}
						out = append(out, a.metric("k8s.endpoint.address_available", available, pt), a.metric("k8s.endpoint.address_not_ready", notReady, pt))
					}
				}
			}
		}
	case "EndpointSlice":
		var available, notReady float64
		endpoints, _ := object["endpoints"].([]any)
		for _, item := range endpoints {
			endpoint, _ := item.(map[string]any)
			ready, specified := mapField(endpoint, "conditions")["ready"].(bool)
			addresses, _ := endpoint["addresses"].([]any)
			if !specified || ready {
				available += float64(len(addresses))
			} else {
				notReady += float64(len(addresses))
			}
		}
		emit("address_available", available)
		emit("address_not_ready", notReady)
	case "PersistentVolume", "PersistentVolumeClaim":
		if phase := stringField(status, "phase"); phase != "" {
			pt := maps.Clone(tags)
			pt["phase"] = phase
			out = append(out, a.metric("k8s."+base+".status", 1, pt))
		}
		if kind == "PersistentVolume" {
			if value, ok := resourceQuantity(mapField(spec, "capacity")["storage"]); ok {
				emit("capacity_bytes", value)
			}
		} else {
			if value, ok := resourceQuantity(mapField(mapField(spec, "resources"), "requests")["storage"]); ok {
				emit("request_storage_bytes", value)
			}
			modes, _ := spec["accessModes"].([]any)
			for _, mode := range modes {
				if value := stringValue(mode); value != "" {
					mt := maps.Clone(tags)
					mt["access_mode"] = value
					out = append(out, a.metric("k8s."+base+".access_mode", 1, mt))
				}
			}
		}
	case "Ingress":
		rules, _ := spec["rules"].([]any)
		for _, item := range rules {
			rule, _ := item.(map[string]any)
			paths, _ := mapField(rule, "http")["paths"].([]any)
			for _, item := range paths {
				path, _ := item.(map[string]any)
				pt := maps.Clone(tags)
				pt["host"] = stringField(rule, "host")
				pt["path"] = stringField(path, "path")
				out = append(out, a.metric("k8s.ingress.path", 1, pt))
			}
		}
		tls, _ := spec["tls"].([]any)
		for _, item := range tls {
			entry, _ := item.(map[string]any)
			hosts, _ := entry["hosts"].([]any)
			for _, host := range hosts {
				ht := maps.Clone(tags)
				ht["host"] = stringValue(host)
				out = append(out, a.metric("k8s.ingress.tls", 1, ht))
			}
		}
	}
	return out
}
