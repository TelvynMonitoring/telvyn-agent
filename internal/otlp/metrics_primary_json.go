package otlp

import "encoding/json"

// Keep exemplar IDs and unknown SDK fields byte-for-byte semantically intact.
func (h *HTTPReceiver) stampMetricsJSON(body []byte, clientIP string) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, err
	}
	var resources []map[string]json.RawMessage
	if len(root["resourceMetrics"]) == 0 {
		return body, nil
	}
	if err := json.Unmarshal(root["resourceMetrics"], &resources); err != nil {
		return nil, err
	}
	values := h.primaryMetadata(clientIP)
	for _, resource := range resources {
		resource["resource"], _ = stampJSONPrimary(resource["resource"], values)
		var scopes []map[string]json.RawMessage
		if len(resource["scopeMetrics"]) == 0 {
			continue
		}
		if err := json.Unmarshal(resource["scopeMetrics"], &scopes); err != nil {
			return nil, err
		}
		for _, scope := range scopes {
			var metrics []map[string]json.RawMessage
			if len(scope["metrics"]) == 0 {
				continue
			}
			if err := json.Unmarshal(scope["metrics"], &metrics); err != nil {
				return nil, err
			}
			for _, metric := range metrics {
				for _, kind := range []string{"gauge", "sum", "histogram", "exponentialHistogram", "summary"} {
					if len(metric[kind]) == 0 {
						continue
					}
					var group map[string]json.RawMessage
					if err := json.Unmarshal(metric[kind], &group); err != nil {
						return nil, err
					}
					var points []json.RawMessage
					if err := json.Unmarshal(group["dataPoints"], &points); err != nil {
						return nil, err
					}
					for i, point := range points {
						points[i], _ = stampJSONPrimary(point, nil)
					}
					group["dataPoints"], _ = json.Marshal(points)
					metric[kind], _ = json.Marshal(group)
				}
			}
			scope["metrics"], _ = json.Marshal(metrics)
		}
		resource["scopeMetrics"], _ = json.Marshal(scopes)
	}
	root["resourceMetrics"], _ = json.Marshal(resources)
	return json.Marshal(root)
}
