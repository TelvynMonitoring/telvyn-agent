package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostProcMountedNeedsHostInitAndDisk(t *testing.T) {
	root := t.TempDir()
	if hostProcMounted(root) {
		t.Fatal("sem /proc do host montado não pode coletar as métricas da máquina")
	}
	if err := os.MkdirAll(filepath.Join(root, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if hostProcMounted(root) {
		t.Fatal("sem o disco do host (1/root) o agent mediria o container")
	}
	if err := os.MkdirAll(filepath.Join(root, "1", "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !hostProcMounted(root) {
		t.Fatal("com 1/root visível o /proc do host está montado")
	}
}
