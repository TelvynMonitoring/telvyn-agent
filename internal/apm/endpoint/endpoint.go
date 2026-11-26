// Package endpoint infere o endpoint de baixa cardinalidade de um span de servidor HTTP que não traz rota.
//
// Aplicações que atendem tudo num só handler (um app.use no Express, um servlet único, um catch-all) não informam
// http.route, e sem isso todas as requisições viriam sob o nome da operação ("GET"). O endpoint inferido troca os
// segmentos que parecem identificadores por {id}: /api/users/42 vira /api/users/{id}.
//
// O mesmo algoritmo, com os mesmos casos de teste, existe no backend (HttpEndpoint): os dois lados têm que concordar.
package endpoint

import (
	"regexp"
	"strings"
)

const (
	maxSegments  = 10
	maxPathBytes = 256
	// Token longo só vira identificador se misturar dígitos, para não esconder slugs descritivos.
	minTokenLen = 20
)

var (
	uuid     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hex      = regexp.MustCompile(`^[0-9a-fA-F]{12,}$`)
	digits   = regexp.MustCompile(`^[0-9]+$`)
	tokenish = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	hasDigit = regexp.MustCompile(`[0-9]`)
)

// Infer devolve "MÉTODO /caminho/{id}", ou vazio quando o span não tem método ou caminho de servidor.
// Só lê url.path e http.target (caminho de quem recebe). O URL completo (url.full, http.url) é de chamada de saída.
func Infer(attrs map[string]string) string {
	method := attrs["http.request.method"]
	if method == "" {
		method = attrs["http.method"]
	}
	path := attrs["url.path"]
	if path == "" {
		path = attrs["http.target"]
	}
	if method == "" || path == "" {
		return ""
	}
	// Um 404 sem rota é um caminho que ninguém atende: robôs que varrem URLs criariam um endpoint por caminho, sem limite.
	status := attrs["http.response.status_code"]
	if status == "" {
		status = attrs["http.status_code"]
	}
	if status == "404" {
		return ""
	}
	normalized := Normalize(path)
	if normalized == "" {
		return ""
	}
	return method + " " + normalized
}

// Normalize troca os segmentos com cara de identificador por {id}, sem consulta nem barra final.
func Normalize(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		return ""
	}
	if len(path) > maxPathBytes {
		path = path[:maxPathBytes]
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 1 && segments[0] == "" {
		return "/"
	}
	out := make([]string, 0, len(segments))
	for i, segment := range segments {
		if i >= maxSegments {
			out = append(out, "…")
			break
		}
		if looksLikeID(segment) {
			segment = "{id}"
		}
		out = append(out, segment)
	}
	return "/" + strings.Join(out, "/")
}

func looksLikeID(segment string) bool {
	switch {
	case digits.MatchString(segment), uuid.MatchString(segment), hex.MatchString(segment):
		return true
	case len(segment) >= minTokenLen && tokenish.MatchString(segment) && hasDigit.MatchString(segment):
		return true
	}
	return false
}
