package checks

import "testing"

func TestMongoCustomDefinitionOnlyAllowsBoundedReads(t *testing.T) {
	if _, err := parseMongoCustomDefinition(`{"operation":"count","collection":"orders","filter":{"status":"open"}}`, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := parseMongoCustomDefinition(`{"operation":"count","collection":"orders","filter":{"$where":"sleep(1000)"}}`, nil); err == nil {
		t.Fatal("executable filter accepted")
	}
	if _, err := parseMongoCustomDefinition(`{"operation":"find","collection":"orders"}`, nil); err == nil {
		t.Fatal("untyped find accepted")
	}
}
