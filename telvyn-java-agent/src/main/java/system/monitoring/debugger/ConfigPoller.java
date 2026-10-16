package system.monitoring.debugger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.ResettableClassFileTransformer;

import java.lang.instrument.Instrumentation;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Config remota (Dbg·4c) — a nossa "Remote Configuration". De tempos em tempos,
 * PUXA do backend a lista de pontos que o usuário ligou na tela
 * ({@code GET <coletor>/v1/debug/config?service=...}) e reaplica em
 * runtime via ByteBuddy (reset do anterior + reinstala o novo) — SEM reiniciar
 * o app.
 *
 * <p>Garantias: só reaplica quando a lista REALMENTE muda; falha de rede não
 * derruba nada (segue com a última lista que tinha); nunca pausa o app.
 */
final class ConfigPoller {

    private final Instrumentation inst;
    private final String url;       // .../v1/debug/config (coletor)
    private final String service;
    private final long intervalSeconds;

    private volatile ResettableClassFileTransformer current;
    private volatile String appliedSig;
    private final String session = java.util.UUID.randomUUID().toString().replace("-", "");

    ConfigPoller(Instrumentation inst, String url, String service,
                 long intervalSeconds, ResettableClassFileTransformer initial, String initialSig) {
        this.inst = inst;
        this.url = url;
        this.service = service;
        this.intervalSeconds = Math.max(3, intervalSeconds);
        this.current = initial;
        this.appliedSig = initialSig;
    }

    void start() {
        Thread t = new Thread(this::loop, "telvyn-debugger-config");
        t.setDaemon(true);
        t.start();
    }

    private void loop() {
        // primeira busca rápida (deixa o app assentar), depois no intervalo
        if (!sleep(2000)) return;
        while (true) {
            try {
                pollOnce();
            } catch (Throwable t) {
                // rede fora / qualquer erro: segue com a última lista, sem barulho
            }
            if (!sleep(intervalSeconds * 1000L)) return;
        }
    }

    private void pollOnce() throws Exception {
        String u = url + (url.contains("?") ? "&" : "?") + "service=" + enc(service);
        if(ProbeMetricSink.environment()!=null)u+="&env="+enc(ProbeMetricSink.environment());
        if(ProbeMetricSink.version()!=null)u+="&version="+enc(ProbeMetricSink.version());
        CollectorHttp.Response res = CollectorHttp.get(u, 10000);
        if (res.status() / 100 != 2) return;

        var body=com.google.gson.JsonParser.parseString(res.body()).getAsJsonObject();
        var probeSpecs=strings(body.get("probes"));var excPrefixes=strings(body.get("exceptions"));
        String configVersion=body.get("config_version").getAsString();if(!configVersion.matches("[a-f0-9]{64}"))return;
        var policies=ProbePolicies.parse(body.get("policies"));
        if(!new java.util.HashSet<>(probeSpecs).equals(policies.stream().map(ProbePolicies.Rule::target).collect(java.util.stream.Collectors.toSet())))return;
        String sig = configVersion;
        if (sig.equals(appliedSig)) { acknowledge(configVersion); return; } // actual proof refresh, not reinstallation

        List<Probe> probes = Probe.parse(String.join(",", probeSpecs));

        // reset-first: tira o anterior (classes voltam ao normal), depois instala o novo.
        ResettableClassFileTransformer prev = current;
        if (prev != null) {
            if(!prev.reset(inst, AgentBuilder.RedefinitionStrategy.RETRANSFORMATION))throw new IllegalStateException("previous debugger transformer could not be reset");
        }
        ProbePolicies.update(policies);
        current = TelvynDebuggerAgent.buildAndInstall(inst, probes, excPrefixes);
        appliedSig = sig;
        acknowledge(configVersion);
        System.out.println("[telvyn-debugger] config remota atualizada: "
                + probes.size() + " ponto(s), " + excPrefixes.size() + " área(s).");
    }

    private void acknowledge(String version) throws Exception {
        var report=new com.google.gson.JsonObject();report.addProperty("service",service);report.addProperty("host",SnapshotSink.host());report.addProperty("session",session);report.addProperty("config_version",version);report.addProperty("environment",ProbeMetricSink.environment());report.addProperty("service_version",ProbeMetricSink.version());report.add("statuses",com.google.gson.JsonParser.parseString(ProbeApplicationStatus.json()));String body=report.toString();
        CollectorHttp.post(url+"/applied",body,10000);
    }
    private static List<String> strings(com.google.gson.JsonElement value){if(value==null||!value.isJsonArray()||value.getAsJsonArray().size()>200)throw new IllegalArgumentException();var result=new ArrayList<String>();for(var entry:value.getAsJsonArray()){if(!entry.isJsonPrimitive()||!entry.getAsJsonPrimitive().isString()||entry.getAsString().length()>512)throw new IllegalArgumentException();result.add(entry.getAsString());}return result;}

    /** Assinatura canônica (ordenada) da config, pra detectar mudança real. */
    static String sig(List<String> probes, List<String> exceptions) {
        List<String> a = new ArrayList<>(probes); Collections.sort(a);
        List<String> b = new ArrayList<>(exceptions); Collections.sort(b);
        return a + "||" + b;
    }

    /**
     * Extrai um array de strings (ex. "probes":[...]) do JSON de resposta. O corpo
     * é gerado pelo nosso backend (formato controlado e simples: dois arrays de
     * strings), então um parser mínimo basta — sem dependência de lib JSON.
     */
    static List<String> extractStringArray(String json, String key) {
        List<String> out = new ArrayList<>();
        if (json == null) return out;
        int k = json.indexOf("\"" + key + "\"");
        if (k < 0) return out;
        int lb = json.indexOf('[', k);
        if (lb < 0) return out;
        int i = lb + 1, n = json.length();
        while (i < n) {
            char c = json.charAt(i);
            if (c == ']') break;
            if (c == '"') {
                StringBuilder sb = new StringBuilder();
                i++;
                while (i < n) {
                    char d = json.charAt(i);
                    if (d == '\\' && i + 1 < n) { sb.append(json.charAt(i + 1)); i += 2; continue; }
                    if (d == '"') { i++; break; }
                    sb.append(d); i++;
                }
                String s = sb.toString().trim();
                if (!s.isEmpty()) out.add(s);
            } else {
                i++;
            }
        }
        return out;
    }

    private static String enc(String s) {
        try { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
        catch (Throwable t) { return s; }
    }

    private static boolean sleep(long ms) {
        try { Thread.sleep(ms); return true; }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
    }
}
