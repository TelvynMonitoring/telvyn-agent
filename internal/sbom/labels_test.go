package sbom

import "testing"

func TestNormalizeRepository(t *testing.T) {
	cases := map[string]string{
		"https://github.com/juice-shop/juice-shop":     "https://github.com/juice-shop/juice-shop",
		"https://github.com/acme/loja.git":             "https://github.com/acme/loja",
		"https://github.com/acme/loja/":                "https://github.com/acme/loja",
		"git@github.com:acme/loja.git":                 "https://github.com/acme/loja",
		"ssh://git@github.com/acme/loja.git":           "https://github.com/acme/loja",
		"git://github.com/acme/loja":                   "https://github.com/acme/loja",
		"http://github.com/acme/loja":                  "https://github.com/acme/loja",
		"https://github.com/acme/loja/tree/main/docs":  "https://github.com/acme/loja",
		"https://gitlab.com/grupo/sub/projeto":         "https://gitlab.com/grupo/sub/projeto",
		"https://gitlab.com/grupo/projeto/-/tree/main": "https://gitlab.com/grupo/projeto",
		"https://git.empresa.com/acme/loja":            "",
		"https://bitbucket.org/acme/loja":              "",
		"https://github.com/so-o-dono":                 "",
		"ftp://github.com/acme/loja":                   "",
		"":                                             "",
	}
	for in, want := range cases {
		if got := normalizeRepository(in); got != want {
			t.Errorf("normalizeRepository(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestNormalizeRevision(t *testing.T) {
	cases := map[string]string{
		"266448a":   "266448a",
		"266448A":   "266448a",
		"“266448a”": "266448a",
		"9bbaecc41791f00b002bc65931cc5ff355fbdb9": "9bbaecc41791f00b002bc65931cc5ff355fbdb9",
		"v1.2.3": "",
		"main":   "",
		"abc12":  "",
		"":       "",
	}
	for in, want := range cases {
		if got := normalizeRevision(in); got != want {
			t.Errorf("normalizeRevision(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestSourceFromInfoComOsRotulosReaisDoJuiceShop(t *testing.T) {
	raw := `{"chainID":"sha256:x","imageSpec":{"config":{"Labels":{"maintainer":"x","org.opencontainers.image.revision":"266448a","org.opencontainers.image.source":"https://github.com/juice-shop/juice-shop","org.opencontainers.image.version":"20.4.0-SNAPSHOT"}}}}`
	got := sourceFromInfo(raw)
	if got.URL != "https://github.com/juice-shop/juice-shop" || got.Revision != "266448a" {
		t.Fatalf("origem = %+v", got)
	}
}

func TestSourceFromInfoSemRotulosDeOrigemNaoDevolveNada(t *testing.T) {
	// Imagem do WebGoat: só rótulos da base Ubuntu.
	raw := `{"imageSpec":{"config":{"Labels":{"maintainer":"WebGoat team","org.opencontainers.image.ref.name":"ubuntu","org.opencontainers.image.version":"24.04"}}}}`
	if got := sourceFromInfo(raw); got != (imageSource{}) {
		t.Fatalf("esperava vazio, veio %+v", got)
	}
	for _, bad := range []string{"", "não é json", `{"imageSpec":{}}`} {
		if got := sourceFromInfo(bad); got != (imageSource{}) {
			t.Errorf("sourceFromInfo(%q) = %+v", bad, got)
		}
	}
}

func TestRotulosAntigosLabelSchema(t *testing.T) {
	got := sourceFromLabels(map[string]string{"org.label-schema.vcs-url": "https://github.com/acme/loja.git", "org.label-schema.vcs-ref": "abcdef0"})
	if got.URL != "https://github.com/acme/loja" || got.Revision != "abcdef0" {
		t.Fatalf("origem = %+v", got)
	}
}

func TestCommitSemRepositorioNaoServe(t *testing.T) {
	if got := sourceFromLabels(map[string]string{"org.opencontainers.image.revision": "abcdef0"}); got != (imageSource{}) {
		t.Fatalf("esperava vazio, veio %+v", got)
	}
}
