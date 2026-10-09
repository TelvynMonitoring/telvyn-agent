package quarkus

import "testing"

func TestParseLineReadsValueNotOptionalTimestamp(t *testing.T) {
	for _, line := range []string{
		`container_memory_usage_bytes{namespace="lab",pod="app"} 445644800 1791342603227`,
		`container_memory_usage_bytes{namespace="lab",pod="app"} 445644800`,
		`container_memory_usage_bytes 445644800 1791342603227`,
		"container_memory_usage_bytes\t445644800\t1791342603227",
	} {
		name, _, value, ok := ParseLine(line)
		if !ok || name != "container_memory_usage_bytes" || value != 445644800 {
			t.Fatalf("%q: %s %v %v", line, name, value, ok)
		}
	}
	_, labels, value, ok := ParseLine(`metric{label="escaped \"quote\", comma"} 3`)
	if !ok || value != 3 || labels["label"] != "escaped \"quote\", comma" {
		t.Fatalf("invalid escaped label: %v %v %v", labels, value, ok)
	}
}
