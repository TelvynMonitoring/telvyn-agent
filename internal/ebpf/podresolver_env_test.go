package ebpf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPodIndexUsaONamespaceComoAmbientePadrao(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[
			{"metadata":{"name":"sem-rotulo","namespace":"loja","labels":{"app":"x"}},"spec":{},"status":{}},
			{"metadata":{"name":"com-rotulo","namespace":"loja","labels":{"telvyn.io/env":"producao"}},"spec":{},"status":{}}]}`))
	}))
	defer srv.Close()
	index, err := (&httpPodLister{url: srv.URL, client: srv.Client()}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := index.ByNsPod["loja/sem-rotulo"].Env; got != "loja" {
		t.Errorf("sem rótulo, Env = %q, quer o namespace", got)
	}
	if got := index.ByNsPod["loja/com-rotulo"].Env; got != "producao" {
		t.Errorf("com rótulo, Env = %q, quer producao", got)
	}
}
