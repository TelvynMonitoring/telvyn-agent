package checks

import (
	"context"
	"maps"
	"strings"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Only ListImages is used. Mounting the runtime socket still grants broader access.
func (c *k8sKubeletCheck) runtimeImages(ctx context.Context, socket, node string) ([]*collectorv1.Metric, error) {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := runtimev1.NewImageServiceClient(conn).ListImages(ctx, &runtimev1.ListImagesRequest{})
	if err != nil {
		return nil, err
	}
	return c.runtimeImageMetrics(response.GetImages(), node), nil
}

func (c *k8sKubeletCheck) runtimeImageMetrics(images []*runtimev1.Image, node string) []*collectorv1.Metric {
	now := timestamppb.Now()
	base := map[string]string{"node": node, "runtime": "containerd"}
	out := []*collectorv1.Metric{c.metric(now, "k8s.node.runtime_images_total", float64(len(images)), base)}
	for _, image := range images {
		seen := map[string]bool{}
		aliases := append([]string{image.GetId()}, image.GetRepoTags()...)
		aliases = append(aliases, image.GetRepoDigests()...)
		for _, ref := range aliases {
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			tags := maps.Clone(base)
			tags["image"], tags["image_id"] = ref, image.GetId()
			if !strings.HasPrefix(ref, "sha256:") {
				repo, _, _ := strings.Cut(ref, "@")
				if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
					tags["image_tag"], repo = repo[colon+1:], repo[:colon]
				}
				tags["image_name"] = repo
				tags["short_image"] = repo[strings.LastIndex(repo, "/")+1:]
			}
			out = append(out, c.metric(now, "k8s.node.runtime_image.size_bytes", float64(image.GetSize()), tags))
		}
	}
	return out
}
