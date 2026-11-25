package endpoint

import "testing"

// Os mesmos casos existem no backend (HttpEndpointTest): os dois lados têm que nomear o endpoint do mesmo jeito.
var cases = []struct {
	path string
	want string
}{
	{"/api/users/42", "/api/users/{id}"},
	{"/api/orders/3f2b8c1e-1111-4222-8333-444455556661", "/api/orders/{id}"},
	{"/api/products", "/api/products"},
	{"/health", "/health"},
	{"/", "/"},
	{"", ""},
	{"/api/users/42/orders/7?expand=1", "/api/users/{id}/orders/{id}"},
	{"/api/users/42/", "/api/users/{id}"},
	{"/files/a1b2c3d4e5f6a7b8c9d0", "/files/{id}"},
	{"/session/xYz9AbCdEfGhIjKlMnOp12", "/session/{id}"},
	{"/v1/items/abc", "/v1/items/abc"},
	{"/static/main.js", "/static/main.js"},
	{"/api/very-long-descriptive-slug-without-digits-in-it", "/api/very-long-descriptive-slug-without-digits-in-it"},
	{"/a/1/b/2/c/3/d/4/e/5/f/6/g/7/h/8/i/9/j/10/k/11", "/a/{id}/b/{id}/c/{id}/d/{id}/e/{id}/…"},
}

func TestNormalize(t *testing.T) {
	for _, c := range cases {
		if got := Normalize(c.path); got != c.want {
			t.Errorf("Normalize(%q) = %q, esperado %q", c.path, got, c.want)
		}
	}
}

func TestInferUsaMetodoECaminhoDoServidor(t *testing.T) {
	attrs := map[string]string{"http.request.method": "GET", "url.path": "/api/users/163"}
	if got := Infer(attrs); got != "GET /api/users/{id}" {
		t.Errorf("Infer = %q", got)
	}
	legacy := map[string]string{"http.method": "POST", "http.target": "/api/orders/9?x=1"}
	if got := Infer(legacy); got != "POST /api/orders/{id}" {
		t.Errorf("Infer (atributos antigos) = %q", got)
	}
}

func TestInferNaoInventaQuandoFaltaMetodoOuCaminho(t *testing.T) {
	if got := Infer(map[string]string{"url.path": "/x/1"}); got != "" {
		t.Errorf("sem método: %q", got)
	}
	if got := Infer(map[string]string{"http.request.method": "GET"}); got != "" {
		t.Errorf("sem caminho: %q", got)
	}
}

func TestInferNaoUsaUrlDeChamadaDeSaida(t *testing.T) {
	// span de cliente: o URL completo é de OUTRO serviço, e misturar hosts daria um endpoint que não existe.
	client := map[string]string{"http.request.method": "GET", "url.full": "http://outro:8080/api/users/42"}
	if got := Infer(client); got != "" {
		t.Errorf("url.full não vale: %q", got)
	}
}

// Um 404 sem rota é um caminho que ninguém atende. Robôs que varrem URLs aleatórias criariam um endpoint por caminho,
// sem limite, e empurrariam os endpoints reais para fora. O 404 fica sob o nome da operação, como antes.
func TestInferNaoCriaEndpointParaRespostaNaoEncontrada(t *testing.T) {
	for _, key := range []string{"http.response.status_code", "http.status_code"} {
		attrs := map[string]string{"http.request.method": "GET", "url.path": "/wp-admin/setup-config.php", key: "404"}
		if got := Infer(attrs); got != "" {
			t.Errorf("404 (%s) não deve criar endpoint: %q", key, got)
		}
	}
	ok := map[string]string{"http.request.method": "GET", "url.path": "/api/users/7", "http.response.status_code": "200"}
	if got := Infer(ok); got != "GET /api/users/{id}" {
		t.Errorf("200 continua inferindo: %q", got)
	}
	other := map[string]string{"http.request.method": "GET", "url.path": "/api/users/7", "http.response.status_code": "500"}
	if got := Infer(other); got != "GET /api/users/{id}" {
		t.Errorf("500 continua inferindo (é um endpoint real com erro): %q", got)
	}
}
