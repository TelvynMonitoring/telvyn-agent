package clusteragent

import (
	"encoding/json"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

var quantityPattern = regexp.MustCompile(`^([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)(n|u|m|k|K|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?$`)

func resourceQuantity(value any) (float64, bool) {
	text, ok := value.(string)
	if !ok {
		return 0, false
	}
	parts := quantityPattern.FindStringSubmatch(text)
	if parts == nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return 0, false
	}
	factor := map[string]float64{"": 1, "n": 1e-9, "u": 1e-6, "m": 1e-3, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "Ki": 1024, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60}[parts[2]]
	n *= factor
	return n, n >= 0 && !math.IsNaN(n) && !math.IsInf(n, 0)
}

func (a *Agent) inventoryMetrics(resources []map[string]any) []*collectorv1.Metric {
	var out []*collectorv1.Metric
	owners := map[string]map[string]any{}
	for _, resource := range resources {
		owners[stringValue(resource["kind"])+"/"+stringValue(resource["namespace"])+"/"+stringValue(resource["name"])] = resource
	}
	for _, resource := range resources {
		details, _ := resource["details"].(map[string]any)
		kind, _ := resource["kind"].(string)
		name, _ := resource["name"].(string)
		tags := map[string]string{"kube_cluster_name": a.cfg.Cluster}
		tags["kube_namespace"], _ = resource["namespace"].(string)
		base := strings.ToLower(kind)
		if kind == "Pod" {
			tags["pod_name"] = name
			tags["kube_node"] = stringValue(resource["node_name"])
			tags["kube_workload_name"] = stringValue(resource["workload_name"])
			tags["kube_workload_kind"] = stringValue(resource["workload_kind"])
			for depth := 0; depth < 2; depth++ {
				owner := owners[tags["kube_workload_kind"]+"/"+tags["kube_namespace"]+"/"+tags["kube_workload_name"]]
				if owner == nil || stringValue(owner["workload_name"]) == "" {
					break
				}
				tags["kube_workload_name"] = stringValue(owner["workload_name"])
				tags["kube_workload_kind"] = stringValue(owner["workload_kind"])
			}
		}
		entityTags := maps.Clone(tags)
		entityTags["kube_"+base] = name
		if kind == "Pod" {
			delete(entityTags, "kube_pod")
			entityTags["pod_name"] = name
		}
		out = append(out, a.metric("k8s."+base+".count", 1, entityTags))
		if created, err := time.Parse(time.RFC3339, stringValue(details["created_at"])); err == nil && (kind == "Node" || kind == "Pod") {
			out = append(out, a.metric("k8s."+base+".age_seconds", time.Since(created).Seconds(), entityTags))
		}
		statusFields := map[string]string{}
		switch kind {
		case "Deployment":
			statusFields = map[string]string{"replicas": "replicas", "updatedReplicas": "replicas_updated", "unavailableReplicas": "replicas_unavailable"}
		case "ReplicaSet":
			statusFields = map[string]string{"replicas": "replicas", "desired_replicas": "replicas_desired", "readyReplicas": "replicas_ready", "fullyLabeledReplicas": "fully_labeled_replicas"}
		case "DaemonSet":
			statusFields = map[string]string{"numberAvailable": "daemons_available", "numberUnavailable": "daemons_unavailable", "desiredNumberScheduled": "desired", "numberMisscheduled": "misscheduled", "numberReady": "ready", "currentNumberScheduled": "scheduled", "updatedNumberScheduled": "updated"}
		case "Job":
			statusFields = map[string]string{"succeeded": "succeeded", "failed": "failed", "active": "active"}
		}
		for field, suffix := range statusFields {
			if value, ok := details[field].(float64); ok {
				out = append(out, a.metric("k8s."+base+"."+suffix, value, entityTags))
			}
		}
		if kind == "Deployment" {
			if paused, ok := details["paused"].(bool); ok {
				value := 0.0
				if paused {
					value = 1
				}
				out = append(out, a.metric("k8s.deployment.paused", value, entityTags))
			}
			rolling := mapField(mapField(details, "strategy"), "rollingUpdate")
			for field, suffix := range map[string]string{"maxSurge": "max_surge", "maxUnavailable": "max_unavailable"} {
				value, ok := rolling[field].(float64)
				if text, isText := rolling[field].(string); isText && strings.HasSuffix(text, "%") {
					pct, err := strconv.ParseFloat(strings.TrimSuffix(text, "%"), 64)
					replicas, known := details["desired_replicas"].(float64)
					if err == nil && known && pct >= 0 {
						value = math.Floor(replicas * pct / 100)
						if field == "maxSurge" {
							value = math.Ceil(replicas * pct / 100)
						}
						ok = true
					}
				}
				if ok && value >= 0 {
					out = append(out, a.metric("k8s.deployment.rollingupdate."+suffix, value, entityTags))
				}
			}
		}
		if kind == "Job" {
			start, e1 := time.Parse(time.RFC3339, stringValue(details["startTime"]))
			end, e2 := time.Parse(time.RFC3339, stringValue(details["completionTime"]))
			if e1 == nil {
				duration := time.Since(start).Seconds()
				if e2 == nil {
					duration = end.Sub(start).Seconds()
					out = append(out, a.metric("k8s.job.completion.succeeded", 1, entityTags))
				}
				if duration >= 0 {
					out = append(out, a.metric("k8s.job.duration_seconds", duration, entityTags))
				}
			}
		}
		if kind == "Service" {
			if typ := stringValue(details["type"]); typ != "" {
				st := maps.Clone(entityTags)
				st["service_type"] = typ
				out = append(out, a.metric("k8s.service.type", 1, st))
			}
		}
		if kind == "Node" || kind == "Pod" || kind == "Deployment" {
			conditions, _ := resource["conditions"].([]any)
			for _, item := range conditions {
				condition, _ := item.(map[string]any)
				status := stringValue(condition["status"])
				if status != "True" && status != "False" && status != "Unknown" {
					continue
				}
				ct := maps.Clone(entityTags)
				ct["condition"] = stringValue(condition["type"])
				ct["condition_status"] = status
				out = append(out, a.metric("k8s."+base+".condition", 1, ct))
				if kind == "Pod" && (ct["condition"] == "Ready" || ct["condition"] == "PodScheduled") {
					metric := "ready"
					if ct["condition"] == "PodScheduled" {
						metric = "scheduled"
					}
					for _, state := range []string{"True", "False", "Unknown"} {
						value := 0.0
						if status == state {
							value = 1
						}
						pt := maps.Clone(entityTags)
						pt["condition"] = strings.ToLower(state)
						out = append(out, a.metric("k8s.pod."+metric, value, pt))
					}
				}
			}
		}
		switch kind {
		case "Node":
			tags["kube_node"] = name
			// Reuse the kubelet's CRI image inventory instead of mounting a new
			// privileged runtime socket. ponytail: kubelet caps this list (usually
			// 50); use an approved CRI reader when complete runtime inventory is needed.
			if images, ok := details["images"].([]any); ok {
				out = append(out, a.metric("k8s.node.images_reported", float64(len(images)), tags))
				for _, item := range images {
					image, _ := item.(map[string]any)
					size, ok := image["sizeBytes"].(float64)
					names, _ := image["names"].([]any)
					if !ok || size < 0 || len(names) == 0 {
						continue
					}
					for _, alias := range names {
						ref := stringValue(alias)
						if ref == "" {
							continue
						}
						it := maps.Clone(tags)
						it["image"] = ref
						repo, _, _ := strings.Cut(ref, "@")
						if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
							it["image_tag"], repo = repo[colon+1:], repo[:colon]
						}
						it["image_name"] = repo
						it["short_image"] = repo[strings.LastIndex(repo, "/")+1:]
						out = append(out, a.metric("k8s.node.image.size_bytes", size, it))
					}
				}
			}
			if unschedulable, ok := details["unschedulable"].(bool); ok {
				st := maps.Clone(tags)
				st["status"] = "schedulable"
				if unschedulable {
					st["status"] = "unschedulable"
				}
				out = append(out, a.metric("k8s.node.status", 1, st))
			}
			for _, scope := range []string{"capacity", "allocatable"} {
				values, _ := details[scope].(map[string]any)
				for key, suffix := range map[string]string{"cpu": "cpu_cores", "memory": "memory_bytes", "pods": "pods", "ephemeral-storage": "ephemeral_storage_bytes"} {
					if value, ok := resourceQuantity(values[key]); ok {
						out = append(out, a.metric("k8s.node."+scope+"."+suffix, value, tags))
					}
				}
			}
		case "Pod":
			claims, _ := details["pvc_volumes"].([]any)
			for _, item := range claims {
				claim, _ := item.(map[string]any)
				vt := maps.Clone(tags)
				vt["volume"] = stringValue(claim["volume"])
				vt["persistentvolumeclaim"] = stringValue(claim["claim"])
				value := 0.0
				if claim["read_only"] == true {
					value = 1
				}
				out = append(out, a.metric("k8s.pod.volumes.persistentvolumeclaims_readonly", value, vt))
			}
			tolerations, _ := details["tolerations"].([]any)
			for _, item := range tolerations {
				toleration, _ := item.(map[string]any)
				tt := maps.Clone(tags)
				for _, key := range []string{"key", "operator", "value", "effect"} {
					if value := stringValue(toleration[key]); value != "" {
						tt["toleration_"+key] = value
					}
				}
				out = append(out, a.metric("k8s.pod.tolerations", 1, tt))
			}
			if phase := stringValue(resource["phase"]); phase != "" {
				pt := maps.Clone(tags)
				pt["pod_phase"] = phase
				out = append(out, a.metric("k8s.pod.status_phase", 1, pt))
			}
			containers, _ := details["containers"].([]any)
			for _, item := range containers {
				container, _ := item.(map[string]any)
				containerName, _ := container["name"].(string)
				if containerName == "" {
					continue
				}
				ct := maps.Clone(tags)
				ct["kube_container_name"] = containerName
				settings, _ := container["resources"].(map[string]any)
				for _, scope := range []string{"requests", "limits"} {
					values, _ := settings[scope].(map[string]any)
					for key, suffix := range map[string]string{"cpu": "cpu_cores", "memory": "memory_bytes", "ephemeral-storage": "ephemeral_storage_bytes"} {
						if value, ok := resourceQuantity(values[key]); ok {
							out = append(out, a.metric("k8s.container."+scope+"."+suffix, value, ct))
						}
					}
				}
			}
			if start, err := time.Parse(time.RFC3339, stringValue(details["startTime"])); err == nil {
				out = append(out, a.metric("k8s.pod.uptime_seconds", time.Since(start).Seconds(), tags))
			}
			for _, family := range []string{"container_statuses", "init_container_statuses"} {
				prefix := "k8s.container."
				if family == "init_container_statuses" {
					prefix = "k8s.initcontainer."
				}
				states, _ := details[family].([]any)
				for _, item := range states {
					state, _ := item.(map[string]any)
					containerName, _ := state["name"].(string)
					if containerName == "" {
						continue
					}
					ct := maps.Clone(tags)
					ct["kube_container_name"] = containerName
					if value, ok := state["restartCount"].(float64); ok {
						out = append(out, a.metric(prefix+"restarts", value, ct))
					}
					if states, ok := state["state"].(map[string]any); ok {
						for _, phase := range []string{"running", "waiting", "terminated"} {
							value := 0.0
							if _, exists := states[phase]; exists {
								value = 1
							}
							out = append(out, a.metric(prefix+phase, value, ct))
							phaseState, _ := states[phase].(map[string]any)
							reason := stringValue(phaseState["reason"])
							allowed := phase == "waiting" && slices.Contains([]string{"errimagepull", "imagepullbackoff", "crashloopbackoff", "containercreating", "createcontainererror", "invalidimagename", "createcontainerconfigerror"}, strings.ToLower(reason)) || phase == "terminated" && slices.Contains([]string{"oomkilled", "containercannotrun", "error"}, strings.ToLower(reason))
							if allowed {
								rt := maps.Clone(ct)
								rt["reason"] = reason
								out = append(out, a.metric(prefix+"status_report.count."+phase, value, rt))
							}
						}
					}
					if ready, ok := state["ready"].(bool); ok {
						value := 0.0
						if ready {
							value = 1
						}
						out = append(out, a.metric(prefix+"ready", value, ct))
					}
				}
			}
		}
	}
	totals := map[string]*collectorv1.Metric{}
	for _, metric := range out {
		node := strings.HasPrefix(metric.MetricName, "k8s.node.capacity.") || strings.HasPrefix(metric.MetricName, "k8s.node.allocatable.")
		container := strings.HasPrefix(metric.MetricName, "k8s.container.requests.") || strings.HasPrefix(metric.MetricName, "k8s.container.limits.")
		if (!node && !container) || (!strings.HasSuffix(metric.MetricName, "cpu_cores") && !strings.HasSuffix(metric.MetricName, "memory_bytes")) {
			continue
		}
		tags := maps.Clone(metric.Tags)
		delete(tags, "kube_node")
		delete(tags, "pod_name")
		name := metric.MetricName + ".total"
		value := metric.Value
		if container {
			pod := owners["Pod/"+metric.Tags["kube_namespace"]+"/"+metric.Tags["pod_name"]]
			phase := stringValue(pod["phase"])
			// Like DD, allocation totals exclude terminal and unscheduled pods;
			// keep their declared per-container requests for investigation.
			if phase == "Succeeded" || phase == "Failed" || metric.Tags["kube_node"] == "" {
				value = 0
			}
		}
		encoded, _ := json.Marshal(tags)
		key := name + string(encoded)
		if total := totals[key]; total != nil {
			total.Value += value
		} else {
			totals[key] = a.metric(name, value, tags)
		}
	}
	for _, metric := range totals {
		out = append(out, metric)
	}
	// Enrich only per-pod samples, after computing allocation totals: pod
	// identity/labels must not split a workload's aggregate into individual pods.
	for _, metric := range out {
		pod := owners["Pod/"+metric.Tags["kube_namespace"]+"/"+metric.Tags["pod_name"]]
		if pod == nil {
			continue
		}
		for key, raw := range map[string]any{"uid": pod["uid"], "pod_phase": pod["phase"]} {
			if value := stringValue(raw); value != "" {
				metric.Tags[key] = value
			}
		}
		if value := stringValue(mapField(pod, "details")["priorityClassName"]); value != "" {
			metric.Tags["kube_priority_class"] = value
		}
		labels := mapField(pod, "labels")
		for key, tag := range map[string]string{"app.kubernetes.io/name": "kube_app_name", "app.kubernetes.io/instance": "kube_app_instance", "app.kubernetes.io/version": "kube_app_version", "app.kubernetes.io/component": "kube_app_component", "app.kubernetes.io/part-of": "kube_app_part_of", "app.kubernetes.io/managed-by": "kube_app_managed_by", "helm.sh/chart": "helm_chart"} {
			if value := stringValue(labels[key]); value != "" {
				metric.Tags[tag] = value
			}
		}
		for key, kind := range map[string]string{"kube_deployment": "Deployment", "kube_replica_set": "ReplicaSet", "kube_stateful_set": "StatefulSet", "kube_daemon_set": "DaemonSet", "kube_job": "Job", "kube_cronjob": "CronJob"} {
			if stringValue(pod["workload_kind"]) == kind && stringValue(pod["workload_name"]) != "" {
				metric.Tags[key] = stringValue(pod["workload_name"])
			}
			if metric.Tags["kube_workload_kind"] == kind && metric.Tags["kube_workload_name"] != "" {
				metric.Tags[key] = metric.Tags["kube_workload_name"]
			}
		}
	}
	return out
}

func stringValue(value any) string { text, _ := value.(string); return text }
