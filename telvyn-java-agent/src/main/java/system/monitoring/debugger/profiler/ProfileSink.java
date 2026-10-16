package system.monitoring.debugger.profiler;

import java.util.List;

/**
 * Envio dos profiles (folded stacks) pro backend. Espelha o cano do
 * {@code SnapshotSink} do debugger (mesmas envs de destino), mas auto-contido pra
 * NÃO tocar no debugger — risco zero pro que já existe.
 *
 * <p>Destino: {@code POST <coletor>/v1/profile}; o coletor Telvyn local repassa ao backend com
 * a credencial dele (a aplicação não guarda credencial).
 *
 * <p>Config (system property OU env): coletor como no {@code SnapshotSink}
 * ({@code TELVYN_AGENT_URL}, senão {@code OTEL_EXPORTER_OTLP_ENDPOINT}, senão http://localhost:4318),
 * {@code TELVYN_SERVICE}/{@code OTEL_SERVICE_NAME}, e opcionais
 * {@code TELVYN_NAMESPACE}/{@code TELVYN_POD_NAMESPACE}/{@code K8S_NAMESPACE} e
 * {@code TELVYN_POD}/{@code TELVYN_POD_NAME}/{@code K8S_POD_NAME} (a identidade k8s
 * que o deploy do backend já exporta via downward API casa direto).
 */
final class ProfileSink {

    private final String url;        // endpoint completo no coletor
    private final String service;
    private final String namespace;
    private final String pod;

    private ProfileSink(String url, String service, String namespace, String pod) {
        this.url = url;
        this.service = service;
        this.namespace = namespace;
        this.pod = pod;
    }

    static ProfileSink fromEnv() {
        String service = firstNonBlank(env("TELVYN_SERVICE"), env("OTEL_SERVICE_NAME"), "java-app");
        String namespace = firstNonBlank(env("TELVYN_NAMESPACE"), env("TELVYN_POD_NAMESPACE"),
                env("K8S_NAMESPACE"), env("MY_POD_NAMESPACE"), "");
        String pod = firstNonBlank(env("TELVYN_POD"), env("TELVYN_POD_NAME"),
                env("K8S_POD_NAME"), env("MY_POD_NAME"), hostname());
        String profileUrl=firstNonBlank(prop("telvyn.profile.ingest.url"),env("TELVYN_PROFILE_INGEST_URL"));
        String url = profileUrl != null ? profileUrl : system.monitoring.debugger.Collector.url() + "/v1/profile";
        return new ProfileSink(url, service, namespace, pod);
    }

    String describe() {
        return "→ " + url + " (service=" + service + ", pod=" + pod + ")";
    }

    void send(String folded, long windowStartMs, int windowSeconds, int periodMs) {
        send(folded, windowStartMs, windowSeconds, periodMs, "cpu");
    }

    /**
     * G3 — mesmo envio, com {@code profileType} explícito (cpu | alloc | lock |
     * wall). Os profilers novos (memória/lock) chamam esta variante; o profiler de
     * CPU original segue chamando a de 4 args acima, sem mudar de comportamento.
     */
    void send(String folded, long windowStartMs, int windowSeconds, int periodMs, String profileType) {
        send(folded,windowStartMs,windowSeconds,periodMs,profileType,List.of());
    }
    void send(String folded, long windowStartMs, int windowSeconds, int periodMs, String profileType, List<LinkedProfileAccumulator.LinkStack> links) {
        send(folded,windowStartMs,windowSeconds,periodMs,profileType,links,null);
    }
    void send(String folded, long windowStartMs, int windowSeconds, int periodMs, String profileType, List<LinkedProfileAccumulator.LinkStack> links, ProfileDetails.Window details) {
        try {
            String body = buildJson(folded, windowStartMs, windowSeconds, periodMs, profileType, links);
            if(details!=null){
                var kept=new java.util.HashMap<String,Long>();
                for(String row:folded.split("\n")){int separator=row.lastIndexOf(' ');if(separator>0)kept.put(row.substring(0,separator),Long.parseLong(row.substring(separator+1).trim()));}
                var originWeights=new java.util.HashMap<String,Long>();
                for(var origin:details.line_stacks())originWeights.merge(origin.folded(),origin.weight(),Math::addExact);
                // Keep exact weights only for origins belonging to the emitted aggregate; never scale them.
                var origins=details.line_stacks().stream().filter(origin->kept.containsKey(origin.folded())&&originWeights.get(origin.folded())<=kept.get(origin.folded())).toList();
                var emitted=new ProfileDetails.Window(details.observed_events(),details.events(),details.allocated_types(),details.stack_groups(),origins,details.window_metrics());
                body=body.substring(0,body.length()-1)+",\"details\":"+new com.google.gson.Gson().toJson(emitted)+"}";
            }
            var resp = system.monitoring.debugger.CollectorHttp.post(url, body, 10000);
            if (resp.status() / 100 != 2) {
                System.err.println("[telvyn-profiler] ingest HTTP " + resp.status() + ": " + cap(resp.body(), 200));
            }
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] envio falhou (app segue normal): " + t);
        }
    }

    /** Monta o JSON do payload. `folded` vai como string única (escapada). */
    String buildJson(String folded, long windowStartMs, int windowSeconds, int periodMs) {
        return buildJson(folded, windowStartMs, windowSeconds, periodMs, "cpu");
    }

    /** G3 — mesma montagem, com {@code profile_type} explícito. */
    String buildJson(String folded, long windowStartMs, int windowSeconds, int periodMs, String profileType) {
        return buildJson(folded,windowStartMs,windowSeconds,periodMs,profileType,List.of());
    }
    String buildJson(String folded, long windowStartMs, int windowSeconds, int periodMs, String profileType, List<LinkedProfileAccumulator.LinkStack> links) {
        StringBuilder sb = new StringBuilder(folded.length() + 256);
        sb.append('{');
        sb.append("\"runtime\":\"jvm\",");
        sb.append("\"service\":\"").append(esc(service)).append("\",");
        String environment = firstNonBlank(prop("telvyn.env"), env("TELVYN_ENV"), resourceAttribute("deployment.environment.name"), resourceAttribute("deployment.environment"));
        String version = firstNonBlank(prop("telvyn.version"), env("TELVYN_VERSION"), resourceAttribute("service.version"));
        if (environment != null) sb.append("\"env\":\"").append(esc(environment)).append("\",");
        if (version != null) sb.append("\"version\":\"").append(esc(version)).append("\",");
        String repository=firstNonBlank(prop("telvyn.git.repository.url"),env("TELVYN_GIT_REPOSITORY_URL"));
        String revision=firstNonBlank(prop("telvyn.git.commit.sha"),env("TELVYN_GIT_COMMIT_SHA"));
        String sourceRoot=firstNonBlank(prop("telvyn.git.source.root"),env("TELVYN_GIT_SOURCE_ROOT"),"src/main/java");
        if(repository!=null&&revision!=null&&revision.matches("[a-fA-F0-9]{40}|[a-fA-F0-9]{64}"))sb.append("\"build_metadata\":{\"repository_url\":\"").append(esc(repository)).append("\",\"commit_sha\":\"").append(esc(revision)).append("\",\"source_root\":\"").append(esc(sourceRoot)).append("\"},");
        sb.append("\"namespace\":\"").append(esc(namespace)).append("\",");
        sb.append("\"pod\":\"").append(esc(pod)).append("\",");
        sb.append("\"host\":\"").append(esc(pod)).append("\",");
        sb.append("\"profile_type\":\"").append(esc(profileType)).append("\",");
        sb.append("\"window_start_unix_ms\":").append(windowStartMs).append(',');
        sb.append("\"window_seconds\":").append(windowSeconds).append(',');
        sb.append("\"period_ms\":").append(periodMs).append(',');
        sb.append("\"folded\":\"").append(esc(folded)).append('"');
        sb.append(",\"sample_links\":[");
        for (int i=0;i<links.size();i++) {
            var link=links.get(i); if(i>0)sb.append(',');
            String endpoint=ProfileEndpointContext.resolve(link.traceId(),link.spanId());
            sb.append("{\"trace_id\":\"").append(link.traceId()).append("\",\"span_id\":\"").append(link.spanId())
                .append("\",\"folded\":\"").append(esc(link.folded())).append('"');
            if(endpoint!=null)sb.append(",\"endpoint\":\"").append(esc(endpoint)).append('"');
            sb.append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    static String resourceAttribute(String key) {
        String attrs = firstNonBlank(prop("otel.resource.attributes"), env("OTEL_RESOURCE_ATTRIBUTES"));
        if (attrs == null) return null;
        for (String item : attrs.split(",")) {
            int equals = item.indexOf('=');
            if (equals > 0 && item.substring(0, equals).trim().equals(key)) return item.substring(equals + 1).trim();
        }
        return null;
    }

    // ---- helpers ----

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private static String cap(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static String hostname() {
        try {
            String h = System.getenv("HOSTNAME");
            if (h != null && !h.isBlank()) return h;
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static String prop(String k) { return blankToNull(System.getProperty(k)); }
    private static String env(String k) { return blankToNull(System.getenv(k)); }
    private static String blankToNull(String s) { return (s == null || s.isBlank()) ? null : s.trim(); }

    private static String firstNonBlank(String... vs) {
        for (String v : vs) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
