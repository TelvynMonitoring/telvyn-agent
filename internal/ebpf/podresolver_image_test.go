package ebpf

import "testing"

func TestImageDigestAceitaOsFormatosDoKubelet(t *testing.T) {
	cases := map[string]string{
		"sha256:abc":                                 "sha256:abc",
		"docker.io/library/postgres@sha256:def":      "sha256:def",
		"docker-pullable://ghcr.io/x/app@sha256:123": "sha256:123",
		"":                                    "",
		"docker.io/library/sem-digest:latest": "",
	}
	for in, want := range cases {
		if got := imageDigest(in); got != want {
			t.Errorf("imageDigest(%q) = %q, quero %q", in, got, want)
		}
	}
}

func TestImageIDForPod(t *testing.T) {
	r := &PodResolverImpl{nsPodImage: map[string]map[string]string{
		"ns/um":   {"app": "sha256:aaa"},
		"ns/dois": {"app": "sha256:bbb", "sidecar": "sha256:ccc"},
	}}
	if got := r.ImageIDForPod("ns", "dois", "sidecar"); got != "sha256:ccc" {
		t.Errorf("container nomeado = %q", got)
	}
	if got := r.ImageIDForPod("ns", "um", ""); got != "sha256:aaa" {
		t.Errorf("pod de um container sem nome = %q", got)
	}
	if got := r.ImageIDForPod("ns", "dois", ""); got != "" {
		t.Errorf("com dois containers e sem nome não pode adivinhar, veio %q", got)
	}
	if got := r.ImageIDForPod("ns", "inexistente", "app"); got != "" {
		t.Errorf("pod desconhecido = %q", got)
	}
}
