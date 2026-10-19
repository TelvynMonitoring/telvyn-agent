package system.monitoring.debugger;

/** Coletor Telvyn local: todo envio da aplicação passa por ele, que repassa ao backend com a credencial dele. */
public final class Collector {
    private Collector() {}

    /** {@code telvyn.agent.url} / {@code TELVYN_AGENT_URL}, senão {@code OTEL_EXPORTER_OTLP_ENDPOINT}, senão http://localhost:4318. */
    public static String url() {
        String base = System.getProperty("telvyn.agent.url");
        for (String env : new String[] {"TELVYN_AGENT_URL", "OTEL_EXPORTER_OTLP_ENDPOINT"}) if (base == null || base.isBlank()) base = System.getenv(env);
        if (base == null || base.isBlank()) base = "http://localhost:4318";
        String b = base.trim();
        while (b.endsWith("/")) b = b.substring(0, b.length() - 1);
        return b;
    }
}
