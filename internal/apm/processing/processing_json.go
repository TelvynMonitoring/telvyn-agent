package processing

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Do not use protojson here: this receiver also accepts hex IDs. Re-encoding
// through protobuf would silently turn those IDs into different base64 values.
func processJSON(body []byte, rules []Rule) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if document == nil {
		return nil, errors.New("invalid OTLP JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing OTLP JSON data")
	}
	resources, err := objects(document, "resourceSpans")
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		for _, rs := range resources {
			resource, ok := rs["resource"].(map[string]any)
			if !ok {
				if rs["resource"] != nil {
					return nil, errors.New("invalid resource")
				}
				resource = map[string]any{}
				rs["resource"] = resource
			}
			attrs, err := objects(resource, "attributes")
			if err != nil {
				return nil, err
			}
			service := jsonAttribute(attrs, "service.name")
			env := jsonAttribute(attrs, "deployment.environment")
			if env == "" {
				env = jsonAttribute(attrs, "deployment.environment.name")
			}
			if rule.Service != nil && *rule.Service != service || rule.Env != nil && *rule.Env != env {
				continue
			}
			switch rule.Action {
			case "remap_service":
				resource["attributes"] = setJSONAttribute(attrs, "service.name", *rule.Value)
			case "remove_attribute", "mask_attribute":
				resource["attributes"] = processJSONAttribute(attrs, *rule.Key, rule.Action)
			}
			scopes, err := objects(rs, "scopeSpans")
			if err != nil {
				return nil, err
			}
			for _, scope := range scopes {
				spans, err := objects(scope, "spans")
				if err != nil {
					return nil, err
				}
				for _, span := range spans {
					attrs, err := objects(span, "attributes")
					if err != nil {
						return nil, err
					}
					switch rule.Action {
					case "remap_resource":
						span["attributes"] = setJSONAttribute(attrs, "resource.name", *rule.Value)
					case "remove_attribute", "mask_attribute":
						span["attributes"] = processJSONAttribute(attrs, *rule.Key, rule.Action)
					}
				}
			}
		}
	}
	return json.Marshal(document)
}

func objects(parent map[string]any, key string) ([]map[string]any, error) {
	if parent[key] == nil {
		return nil, nil
	}
	if values, ok := parent[key].([]map[string]any); ok {
		return values, nil
	}
	values, ok := parent[key].([]any)
	if !ok {
		return nil, errors.New("invalid OTLP JSON array: " + key)
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid OTLP JSON entry: " + key)
		}
		result = append(result, object)
	}
	return result, nil
}

func jsonAttribute(attrs []map[string]any, key string) string {
	for _, attr := range attrs {
		if attr["key"] == key {
			if value, ok := attr["value"].(map[string]any); ok {
				result, _ := value["stringValue"].(string)
				return result
			}
		}
	}
	return ""
}

func setJSONAttribute(attrs []map[string]any, key, value string) []map[string]any {
	found := false
	for _, attr := range attrs {
		if attr["key"] == key {
			attr["value"] = map[string]any{"stringValue": value}
			found = true
		}
	}
	if !found {
		attrs = append(attrs, map[string]any{"key": key, "value": map[string]any{"stringValue": value}})
	}
	return attrs
}

func processJSONAttribute(attrs []map[string]any, key, action string) []map[string]any {
	result := make([]map[string]any, 0, len(attrs))
	for _, attr := range attrs {
		if attr["key"] == key {
			if action == "remove_attribute" {
				continue
			}
			attr["value"] = map[string]any{"stringValue": "[REDACTED]"}
		}
		result = append(result, attr)
	}
	return result
}
