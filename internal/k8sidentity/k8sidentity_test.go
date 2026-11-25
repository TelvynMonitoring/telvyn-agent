package k8sidentity

import "testing"

func TestEnvironment(t *testing.T) {
	cases := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		namespace   string
		want        string
	}{
		{"rótulo telvyn.io/env vence o namespace", map[string]string{"telvyn.io/env": "prod"}, nil, "loja", "prod"},
		{"anotação de ambiente do OpenTelemetry", nil, map[string]string{"resource.opentelemetry.io/deployment.environment": "stg"}, "loja", "stg"},
		{"sem rótulo, o namespace é o ambiente", map[string]string{"app": "x"}, nil, "loja", "loja"},
		{"rótulo vazio conta como ausente", map[string]string{"telvyn.io/env": ""}, nil, "loja", "loja"},
		{"sem rótulo e sem namespace fica vazio", nil, nil, "", ""},
		{"rótulo do Datadog não é lido", map[string]string{"tags.datadoghq.com/env": "dd"}, nil, "loja", "loja"},
	}
	for _, c := range cases {
		if got := Environment(c.labels, c.annotations, c.namespace); got != c.want {
			t.Errorf("%s: Environment = %q, quer %q", c.name, got, c.want)
		}
	}
}
