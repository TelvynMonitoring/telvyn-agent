// Package k8sidentity lê a identidade de um serviço (nome, ambiente e versão) dos rótulos e anotações abertos de um
// pod: telvyn.io/* primeiro, depois os do OpenTelemetry (resource.opentelemetry.io/*) e os recomendados do Kubernetes
// (app.kubernetes.io/*). Webhook, eBPF e SBOM usam a mesma regra, para o serviço ter o mesmo nome em todo sinal.
package k8sidentity

const (
	Service = "service"
	Env     = "env"
	Version = "version"
)

var keys = map[string][]string{
	Service: {"telvyn.io/service", "resource.opentelemetry.io/service.name", "app.kubernetes.io/name"},
	Env:     {"telvyn.io/env", "resource.opentelemetry.io/deployment.environment"},
	Version: {"telvyn.io/version", "resource.opentelemetry.io/service.version", "app.kubernetes.io/version"},
}

// Lookup devolve o primeiro valor não vazio entre os rótulos e as anotações; vazio se nenhum existir.
func Lookup(labels, annotations map[string]string, kind string) string {
	for _, key := range keys[kind] {
		if value := labels[key]; value != "" {
			return value
		}
		if value := annotations[key]; value != "" {
			return value
		}
	}
	return ""
}
