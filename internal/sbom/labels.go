package sbom

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// imageSource é o repositório e o commit que a imagem declara nos rótulos OCI. O Telvyn os usa para mostrar o código
// de um achado sem o cliente precisar informar o commit de cada versão.
type imageSource struct {
	URL      string
	Revision string
}

var (
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	repoPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$`)
	scpPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]+@([A-Za-z0-9.-]+):(.+)$`)
)

// Rótulos que declaram a origem da imagem, em ordem de preferência.
var (
	sourceLabels   = []string{"org.opencontainers.image.source", "org.label-schema.vcs-url"}
	revisionLabels = []string{"org.opencontainers.image.revision", "org.label-schema.vcs-ref"}
)

// imageSource consulta o runtime pelo CRI (ImageStatus verboso, o mesmo que `crictl inspecti`), que devolve a configuração
// OCI da imagem. Qualquer falha devolve vazio: os rótulos são um complemento e nunca impedem o envio do SBOM.
func (s *Scanner) imageSource(ctx context.Context, ref string) imageSource {
	if s.cfg.ContainerdAddr == "" || ref == "" {
		return imageSource{}
	}
	conn, err := grpc.NewClient("unix://"+s.cfg.ContainerdAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return imageSource{}
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := runtimev1.NewImageServiceClient(conn).ImageStatus(ctx, &runtimev1.ImageStatusRequest{Image: &runtimev1.ImageSpec{Image: ref}, Verbose: true})
	if err != nil {
		s.log.Debug("sbom: rótulos da imagem indisponíveis", "image", ref, "err", err)
		return imageSource{}
	}
	return sourceFromInfo(response.GetInfo()["info"])
}

// sourceFromInfo lê o JSON "info" do ImageStatus ({"imageSpec":{"config":{"Labels":{...}}}}).
func sourceFromInfo(raw string) imageSource {
	var info struct {
		ImageSpec struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		} `json:"imageSpec"`
	}
	if raw == "" || json.Unmarshal([]byte(raw), &info) != nil {
		return imageSource{}
	}
	return sourceFromLabels(info.ImageSpec.Config.Labels)
}

func sourceFromLabels(labels map[string]string) imageSource {
	var out imageSource
	for _, key := range sourceLabels {
		if out.URL = normalizeRepository(labels[key]); out.URL != "" {
			break
		}
	}
	for _, key := range revisionLabels {
		if out.Revision = normalizeRevision(labels[key]); out.Revision != "" {
			break
		}
	}
	// Um commit sem repositório (ou o contrário) não leva a lugar nenhum.
	if out.URL == "" || out.Revision == "" {
		return imageSource{}
	}
	return out
}

// normalizeRepository devolve a URL https de um repositório do GitHub ou do GitLab (únicos provedores suportados), ou vazio.
func normalizeRepository(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" || len(text) > 1024 {
		return ""
	}
	if match := scpPattern.FindStringSubmatch(text); match != nil && !strings.Contains(text, "://") {
		text = "https://" + match[1] + "/" + strings.TrimPrefix(match[2], "/")
	}
	parsed, err := url.Parse(text)
	if err != nil || parsed.Host == "" {
		return ""
	}
	switch parsed.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "github.com" && host != "gitlab.com" {
		return ""
	}
	path := strings.TrimSuffix(strings.TrimRight(parsed.Path, "/"), ".git")
	// Links para uma árvore ou arquivo dentro do repositório: fica o repositório.
	for _, marker := range []string{"/-/tree/", "/-/blob/", "/tree/", "/blob/"} {
		if i := strings.Index(path, marker); i >= 0 {
			path = path[:i]
		}
	}
	if !repoPathPattern.MatchString(path) || (host == "github.com" && strings.Count(path, "/") != 2) {
		return ""
	}
	return "https://" + host + path
}

// normalizeRevision aceita o commit completo ou abreviado (7 a 64 hexadecimais); versões como "v1.2.3" não valem.
func normalizeRevision(raw string) string {
	text := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "\"'“”"))
	if revisionPattern.MatchString(text) {
		return text
	}
	return ""
}
