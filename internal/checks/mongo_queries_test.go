package checks

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestMongoProfileLabelDoesNotExposeCommands(t *testing.T) {
	label := mongoProfileLabel(bson.M{"op": "query", "ns": "app.orders", "planSummary": "IXSCAN",
		"command": bson.M{"find": "orders", "filter": bson.M{"email": "private@example.test"}}})
	if label != "query app.orders IXSCAN" || strings.Contains(label, "private@example.test") {
		t.Fatalf("unsafe profile label: %q", label)
	}
}
