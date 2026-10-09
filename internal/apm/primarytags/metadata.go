package primarytags

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var keyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`)

func ValidKey(key string) bool {
	if len(key) > 384 {
		return false
	}
	switch key {
	case "host", "kube_cluster_name", "kube_namespace", "kube_node":
		return true
	}
	suffix := ""
	if strings.HasPrefix(key, "host.tag.") {
		suffix = strings.TrimPrefix(key, "host.tag.")
	} else if strings.HasPrefix(key, "kube_label.") {
		suffix = strings.TrimPrefix(key, "kube_label.")
	}
	return keyPattern.MatchString(suffix)
}
func ValidValue(value string) bool {
	return len([]rune(value)) <= 200 && value != "__other__" && strings.IndexFunc(value, unicode.IsControl) < 0
}

// ParseHostTags reads operator configuration only; never tracer resource attributes.
func ParseHostTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return tags, nil
	}
	if len(raw) > 65536 {
		return nil, fmt.Errorf("host tags configuration too large")
	}
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		return nil, err
	}
	if len(tags) > 256 {
		return nil, fmt.Errorf("maximum 256 host tag keys")
	}
	for key, value := range tags {
		if !ValidKey("host.tag."+key) || !ValidValue(value) {
			return nil, fmt.Errorf("invalid configured host tag")
		}
	}
	return tags, nil
}
