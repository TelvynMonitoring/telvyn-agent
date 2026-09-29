package checks

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestMongoReplicaMembers(t *testing.T) {
	now := time.Now().UTC()
	members := mongoReplicaMembers(bson.M{"members": bson.A{
		bson.M{"name": "primary:27017", "stateStr": "PRIMARY", "optimeDate": primitive.NewDateTimeFromTime(now)},
		bson.M{"name": "secondary:27017", "stateStr": "SECONDARY", "optimeDate": primitive.NewDateTimeFromTime(now.Add(-3 * time.Second))},
	}})
	if len(members) != 2 || members[1].Identity != "secondary:27017" ||
		members[1].ReplayLagSeconds == nil || *members[1].ReplayLagSeconds != 3 {
		t.Fatalf("replica status: %+v", members)
	}
}
