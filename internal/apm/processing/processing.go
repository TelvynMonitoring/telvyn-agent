// Package processing applies ordered, literal APM rules before statistics and sampling.
// It does not replace mandatory obfuscation of SQL, URLs and credentials.
package processing

import (
	"errors"
	"strings"
	"sync/atomic"
	"unicode"

	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

type Rule struct {
	Name    string  `json:"name"`
	Enabled *bool   `json:"enabled"`
	Service *string `json:"service"`
	Env     *string `json:"env"`
	Action  string  `json:"action"`
	Key     *string `json:"key"`
	Value   *string `json:"value"`
}

type Policy struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Processor struct{ policy atomic.Pointer[Policy] }

func (p *Processor) Update(policy Policy) error {
	if policy.Version != 1 || len(policy.Rules) > 50 {
		return errors.New("invalid processing policy")
	}
	for _, rule := range policy.Rules {
		if !valid(rule.Name, 100, false) || !optionalValid(rule.Service, 255) || !optionalValid(rule.Env, 200) {
			return errors.New("invalid processing condition")
		}
		switch rule.Action {
		case "mask_attribute", "remove_attribute":
			if rule.Key == nil || !valid(*rule.Key, 256, false) || protected(*rule.Key) || rule.Value != nil {
				return errors.New("invalid attribute processor")
			}
		case "remap_service", "remap_resource":
			limit := 512
			if rule.Action == "remap_service" {
				limit = 255
			}
			if rule.Key != nil || rule.Value == nil || !valid(*rule.Value, limit, false) {
				return errors.New("invalid remapping processor")
			}
		default:
			return errors.New("unsupported processing action")
		}
	}
	// Configuration is copied before publication; callers may reuse their decoded object.
	copyPolicy := Policy{Version: policy.Version, Rules: make([]Rule, len(policy.Rules))}
	for i, rule := range policy.Rules {
		rule.Service = copyString(rule.Service)
		rule.Env = copyString(rule.Env)
		rule.Key = copyString(rule.Key)
		rule.Value = copyString(rule.Value)
		if rule.Enabled != nil {
			enabled := *rule.Enabled
			rule.Enabled = &enabled
		}
		copyPolicy.Rules[i] = rule
	}
	p.policy.Store(&copyPolicy)
	return nil
}

func (p *Processor) ProcessTraces(contentType string, body []byte) ([]byte, error) {
	policy := p.policy.Load()
	if policy == nil || len(policy.Rules) == 0 {
		return body, nil
	}
	request := &tracepb.ExportTraceServiceRequest{}
	isJSON := strings.Contains(strings.ToLower(contentType), "json")
	if isJSON {
		return processJSON(body, policy.Rules)
	}
	var err error
	err = proto.Unmarshal(body, request)
	if err != nil {
		return nil, err
	}
	for _, rule := range policy.Rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		for _, resource := range request.ResourceSpans {
			if resource == nil {
				continue
			}
			if resource.Resource == nil {
				resource.Resource = &resourcepb.Resource{}
			}
			attrs := resource.Resource.Attributes
			service := attribute(attrs, "service.name")
			env := attribute(attrs, "deployment.environment")
			if env == "" {
				env = attribute(attrs, "deployment.environment.name")
			}
			if rule.Service != nil && *rule.Service != service || rule.Env != nil && *rule.Env != env {
				continue
			}
			switch rule.Action {
			case "remap_service":
				resource.Resource.Attributes = setAttribute(attrs, "service.name", *rule.Value)
			case "remove_attribute", "mask_attribute":
				resource.Resource.Attributes = processAttribute(attrs, *rule.Key, rule.Action)
			}
			for _, scope := range resource.ScopeSpans {
				if scope == nil {
					continue
				}
				for _, span := range scope.Spans {
					if span == nil {
						continue
					}
					switch rule.Action {
					case "remap_resource":
						span.Attributes = setAttribute(span.Attributes, "resource.name", *rule.Value)
					case "remove_attribute", "mask_attribute":
						span.Attributes = processAttribute(span.Attributes, *rule.Key, rule.Action)
					}
				}
			}
		}
	}
	return proto.Marshal(request)
}

func attribute(attrs []*commonpb.KeyValue, key string) string {
	for _, attr := range attrs {
		if attr != nil && attr.Key == key {
			return attr.Value.GetStringValue()
		}
	}
	return ""
}

func setAttribute(attrs []*commonpb.KeyValue, key, value string) []*commonpb.KeyValue {
	newValue := &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
	found := false
	for _, attr := range attrs {
		if attr != nil && attr.Key == key {
			attr.Value = newValue
			found = true
		}
	}
	if found {
		return attrs
	}
	return append(attrs, &commonpb.KeyValue{Key: key, Value: newValue})
}

func processAttribute(attrs []*commonpb.KeyValue, key, action string) []*commonpb.KeyValue {
	out := attrs[:0]
	for _, attr := range attrs {
		if attr != nil && attr.Key == key {
			if action == "remove_attribute" {
				continue
			}
			attr.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "[REDACTED]"}}
		}
		out = append(out, attr)
	}
	return out
}

func protected(key string) bool {
	switch key {
	case "service.name", "deployment.environment", "deployment.environment.name", "telvyn.source", "resource.name":
		return true
	}
	return false
}

func valid(value string, max int, empty bool) bool {
	return len(value) <= max && (empty || strings.TrimSpace(value) != "") && strings.IndexFunc(value, unicode.IsControl) < 0
}

func optionalValid(value *string, max int) bool { return value == nil || valid(*value, max, true) }
func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
