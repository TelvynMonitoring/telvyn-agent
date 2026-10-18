package system.monitoring.debugger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.ResettableClassFileTransformer;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Ponto de entrada do javaagent. A JVM chama {@code premain} (anexo no boot,
 * via {@code -javaagent}) ou {@code agentmain} (anexo em runtime). Instala um
 * {@link AgentBuilder} do ByteBuddy que reescreve, em runtime, os métodos
 * configurados pra injetar a foto. Nada é pausado — só observado.
 *
 * <p>De onde vêm os pontos:
 * <ul>
 *   <li><b>Bootstrap local</b>: system property {@code telvyn.debug.probes} → env
 *       {@code TELVYN_DEBUG_PROBES} → argumento do {@code -javaagent:...=...}
 *       (formato {@code classe#metodo,classe#metodo}); e
 *       {@code telvyn.debug.exceptions}/{@code TELVYN_DEBUG_EXCEPTIONS} (prefixos
 *       de pacote pro Exception Replay).</li>
 *   <li><b>Config remota (Dbg·4c)</b>: se houver destino de ingest configurado,
 *       um {@link ConfigPoller} PUXA do servidor a lista que o usuário ligou na
 *       tela e reaplica sozinho, sem reiniciar. Desligar: {@code telvyn.debug.remote=false}.</li>
 * </ul>
 */
public final class TelvynDebuggerAgent {

    private TelvynDebuggerAgent() {}

    public static void premain(String args, Instrumentation inst) {
        safeInstall(args, inst);
    }

    public static void agentmain(String args, Instrumentation inst) {
        safeInstall(args, inst);
    }

    // Why an installation step failed, in one short line, so the operator can act on it; never more than the error class and message.
    // Startup failures keep the application running; every sensor gets its own single-line reason, like the Node SDK.
    private static void startupFailure(String sensor, Throwable failure) {
        System.err.println("[telvyn] " + sensor + " sensor could not start; application startup continues." + reason(failure));
    }

    static String reason(Throwable failure) {
        String message = failure.getMessage() == null ? "" : failure.getMessage().replaceAll("\\s+", " ");
        if (message.length() > 160) message = message.substring(0, 160);
        return " (" + failure.getClass().getSimpleName() + (message.isEmpty() ? "" : ": " + message) + ")";
    }

    /** Blindagem: qualquer falha na instalação NUNCA pode impedir o app de subir. */
    private static void safeInstall(String args, Instrumentation inst) {
        if("iast-only".equals(args)) {
            try { IastInstrumentation.install(inst); } catch(Throwable failure) { SecuritySensorState.iastFailed();startupFailure("IAST",failure); }
            try { IastJdk.install(inst); } catch(Throwable failure) { startupFailure("IAST (JDK classes)",failure); }
            return;
        }
        try {
            install(args, inst);
        } catch (Throwable t) {
            System.err.println("[telvyn-debugger] desligado (falha na instalação, app segue normal): " + t);
        }
    }

    private static void install(String args, Instrumentation inst) {
        try { SpringMvcSecurity.install(inst); } catch(Throwable failure) { SecuritySensorState.attackFailed();startupFailure("Spring security",failure); }
        try { ServletSecurity.install(inst); } catch(Throwable failure) { startupFailure("Servlet security",failure); }
        try { UserActivity.install(inst); } catch(Throwable failure) { startupFailure("User activity",failure); }
        try { VertxSecurity.install(inst); } catch(Throwable failure) { startupFailure("Vert.x security",failure); }
        try { JaxRsSecurity.install(inst); } catch(Throwable failure) { startupFailure("JAX-RS security",failure); }
        try { GrizzlySecurity.install(inst); } catch(Throwable failure) { startupFailure("Grizzly security",failure); }
        try { NettySecurity.install(inst); } catch(Throwable failure) { startupFailure("Netty security",failure); }
        try { RatpackSecurity.install(inst); } catch(Throwable failure) { startupFailure("Ratpack security",failure); }
        try { ServletBody.install(inst); } catch(Throwable failure) { startupFailure("Servlet body security",failure); }
        try { GraphqlJavaSecurity.install(inst); } catch(Throwable failure) { startupFailure("graphql-java security",failure); }
        try { GrpcSecurity.install(inst); } catch(Throwable failure) { startupFailure("gRPC security",failure); }
        try { AkkaHttpSecurity.install(inst); } catch(Throwable failure) { startupFailure("Akka/Pekko HTTP security",failure); }
        // Exploit prevention instrumenta classes do JDK: só com a detecção de ataques ligada na aplicação, como o Datadog.
        if (Boolean.parseBoolean(System.getProperty("telvyn.security.enabled", System.getenv().getOrDefault("TELVYN_SECURITY_ENABLED", "false"))))
            try { JavaRasp.install(inst); } catch(Throwable failure) { startupFailure("Exploit prevention",failure); }
        // Regras do WAF carregadas na subida, fora das threads da aplicação: a primeira requisição não espera
        // (num event loop do Vert.x/Quarkus a carga travaria a thread).
        if (Boolean.parseBoolean(System.getProperty("telvyn.security.enabled", System.getenv().getOrDefault("TELVYN_SECURITY_ENABLED", "false")))) {
            Thread warmup = new Thread(() -> { try { SpringMvcSecurity.wafReporter(); } catch (Throwable failure) { /* falha já relatada pelo sensor */ } }, "telvyn-security-warmup");
            warmup.setDaemon(true);
            warmup.start();
        }
        try { IastInstrumentation.install(inst); } catch(Throwable failure) { SecuritySensorState.iastFailed();startupFailure("IAST",failure); }
        try { ServletIast.install(inst); } catch(Throwable failure) { startupFailure("IAST (servlet)",failure); }
        try { JdbcIast.install(inst); } catch(Throwable failure) { startupFailure("IAST (JDBC)",failure); }
        try { IastJdk.install(inst); } catch(Throwable failure) { startupFailure("IAST (JDK classes)",failure); }
        try { ScaLibraries.install(inst); } catch(Throwable failure) { startupFailure("SCA",failure); }
        try { SdkConfigurationReporter.start(); } catch (Throwable ignored) { /* Configuration reporting cannot disable instrumentation. */ }
        try { RemoteConfig.start(); } catch (Throwable ignored) { /* Remote configuration cannot disable instrumentation. */ }
        // 1) bootstrap local (env/sysprop/arg) — vale até a primeira busca remota.
        final List<Probe> probes = Probe.parse(firstNonBlank(
                System.getProperty("telvyn.debug.probes"), System.getenv("TELVYN_DEBUG_PROBES"), args));
        final List<String> excPrefixes = parsePrefixes(firstNonBlank(
                System.getProperty("telvyn.debug.exceptions"), System.getenv("TELVYN_DEBUG_EXCEPTIONS")));

        ResettableClassFileTransformer initial = buildAndInstall(inst, probes, excPrefixes);
        if (!probes.isEmpty()) System.out.println("[telvyn-debugger] probes (foto sempre) = " + probes);
        if (!excPrefixes.isEmpty()) System.out.println("[telvyn-debugger] exception-replay (foto só no erro) em = " + excPrefixes);

        // 2) config remota: puxa a lista da tela e reaplica sozinho.
        String configUrl = SnapshotSink.configUrl();
        boolean remoteOn = !"false".equalsIgnoreCase(
                firstNonBlank(System.getProperty("telvyn.debug.remote"), System.getenv("TELVYN_DEBUG_REMOTE"), "true"));

        if (remoteOn) {
            long interval = parseLong(firstNonBlank(
                    System.getProperty("telvyn.debug.remote.interval"),
                    System.getenv("TELVYN_DEBUG_REMOTE_INTERVAL")), 30);
            List<String> initSpecs = new ArrayList<>();
            for (Probe p : probes) initSpecs.add(p.toString());
            String initialSig = ConfigPoller.sig(initSpecs, excPrefixes);
            new ConfigPoller(inst, configUrl, SnapshotSink.service(),
                    interval, initial, initialSig).start();
            System.out.println("[telvyn-debugger] config remota ligada (a cada "
                    + Math.max(3, interval) + "s) — puxando os pontos da tela.");
        } else if (initial == null) {
            System.out.println("[telvyn-debugger] sem probes, sem exception-replay e sem config remota. inativo.");
        }

        try {
            for(String kind:List.of("","exceptions.","retention.","wall.events.","alloc.","lock.")) {
                String environment="TELVYN_PROFILING_"+kind.toUpperCase(java.util.Locale.ROOT).replace('.','_')+"ENABLED";
                if("true".equalsIgnoreCase(firstNonBlank(System.getProperty("telvyn.profiling."+kind+"enabled"),System.getenv(environment),"false"))) {
                    system.monitoring.debugger.profiler.ProfileSourceFiles.install(inst);break;
                }
            }
        } catch(Throwable ignored) { /* Missing source metadata must not disable profiling. */ }

        // 3) Profiler contínuo JFR e hooks de contexto/threads virtuais.
        //    Atrás de flag, DESLIGADO por padrão. Qualquer
        //    falha aqui nunca pode impedir o app de subir (try/catch dedicado).
        try {
            boolean profilingOn = "true".equalsIgnoreCase(firstNonBlank(
                    System.getProperty("telvyn.profiling.enabled"),
                    System.getenv("TELVYN_PROFILING_ENABLED"), "false"));
            system.monitoring.debugger.profiler.ProfilerControl.init(inst);
            if (profilingOn) {
                system.monitoring.debugger.profiler.ProfilerControl.startCpu();
            }
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] desligado (falha, app segue normal): " + t);
        }

        try {
            boolean exceptionsOn = "true".equalsIgnoreCase(firstNonBlank(
                    System.getProperty("telvyn.profiling.exceptions.enabled"),
                    System.getenv("TELVYN_PROFILING_EXCEPTIONS_ENABLED"), "false"));
            if (exceptionsOn) {
                system.monitoring.debugger.profiler.ProfilerControl.startExceptions();
            }
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] exceptions desligado (falha, app segue normal): " + t);
        }

        try {
            if ("true".equalsIgnoreCase(firstNonBlank(System.getProperty("telvyn.profiling.retention.enabled"), System.getenv("TELVYN_PROFILING_RETENTION_ENABLED"), "false")))
                system.monitoring.debugger.profiler.JfrRetentionProfiler.start();
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] retention desligado: " + t.getClass().getSimpleName());
        }

        // 3b) G3 — profiler de MEMÓRIA (alocação) e LOCK (contenção). Mesmo
        //     mecanismo JFR/passivo, cada um atrás da SUA flag (default desligado);
        //     ligar um não afeta os outros nem o profiler de CPU acima.
        int flushSec = (int) parseLong(firstNonBlank(
                System.getProperty("telvyn.profiling.flush.sec"),
                System.getenv("TELVYN_PROFILING_FLUSH_SEC")), 15);
        if ("true".equalsIgnoreCase(firstNonBlank(System.getProperty("telvyn.profiling.wall.events.enabled"), System.getenv("TELVYN_PROFILING_WALL_EVENTS_ENABLED"), "false"))) {
            system.monitoring.debugger.profiler.JfrGenericProfiler.start("wall_events",
                    java.util.List.of("jdk.ThreadSleep", "jdk.ThreadPark", "jdk.JavaMonitorWait", "jdk.JavaMonitorEnter", "jdk.SocketRead", "jdk.SocketWrite", "jdk.FileRead", "jdk.FileWrite", "jdk.VirtualThreadPinned"),
                    settings -> settings.withStackTrace().withThreshold(java.time.Duration.ofMillis(10)),
                    event -> event.getDuration().toNanos(), flushSec);
        }
        try {
            boolean allocOn = "true".equalsIgnoreCase(firstNonBlank(
                    System.getProperty("telvyn.profiling.alloc.enabled"),
                    System.getenv("TELVYN_PROFILING_ALLOC_ENABLED"), "false"));
            if (allocOn) {
                system.monitoring.debugger.profiler.ProfilerControl.startAlloc();
            }
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] alloc desligado (falha, app segue normal): " + t);
        }
        try {
            boolean lockOn = "true".equalsIgnoreCase(firstNonBlank(
                    System.getProperty("telvyn.profiling.lock.enabled"),
                    System.getenv("TELVYN_PROFILING_LOCK_ENABLED"), "false"));
            if (lockOn) {
                system.monitoring.debugger.profiler.ProfilerControl.startLock();
            }
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] lock desligado (falha, app segue normal): " + t);
        }
        // Class Load (as in Datadog): classes loaded, counted per method that caused the load.
        try {
            if ("true".equalsIgnoreCase(firstNonBlank(System.getProperty("telvyn.profiling.classload.enabled"), System.getenv("TELVYN_PROFILING_CLASSLOAD_ENABLED"), "false")))
                system.monitoring.debugger.profiler.JfrGenericProfiler.start("class_load", "jdk.ClassLoad",
                        settings -> settings.withStackTrace().withThreshold(java.time.Duration.ZERO), event -> 1L, flushSec);
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] class load desligado (falha, app segue normal): " + t);
        }
    }

    /**
     * Monta e instala o transformer pra um conjunto de pontos. Devolve o
     * {@link ResettableClassFileTransformer} (pra a config remota poder resetar
     * e trocar depois), ou {@code null} se não há nada pra instrumentar.
     */
    static ResettableClassFileTransformer buildAndInstall(
            Instrumentation inst, List<Probe> probes, List<String> excPrefixes) {
        ProbeApplicationStatus.prepare(probes);

        if ((probes == null || probes.isEmpty()) && (excPrefixes == null || excPrefixes.isEmpty())) {
            return null;
        }

        // REDEFINE (não REBASE): reescreve o corpo do método NO LUGAR, sem adicionar
        // métodos. É o que permite reaplicar em classe JÁ carregada (retransform) —
        // REBASE adicionaria método e o retransform proíbe mudar o "formato" da classe.
        boolean verbose = !"false".equalsIgnoreCase(firstNonBlank(
                System.getProperty("telvyn.debug.verbose"), System.getenv("TELVYN_DEBUG_VERBOSE"), "false"));
        // disableClassFormatChanges(): modo compatível com RETRANSFORMATION de classe
        // JÁ carregada (reescreve corpo no lugar, sem adicionar membros). É a config
        // canônica pra reaplicar ao vivo — sem ela o ByteBuddy "transforma" mas a JVM
        // não passa a chamar o código novo.
        AgentBuilder.RedefinitionListenable.WithoutBatchStrategy redef =
                new AgentBuilder.Default()
                        .disableClassFormatChanges()
                        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION);
        AgentBuilder ab = redef;
        if (verbose) {
            ab = redef.with(AgentBuilder.RedefinitionStrategy.Listener.StreamWriting.toSystemError())
                      .with(AgentBuilder.Listener.StreamWriting.toSystemError());
        }
        AgentBuilder.Listener applicationProof = new AgentBuilder.Listener.Adapter() {
            @Override public void onTransformation(TypeDescription type, ClassLoader loader, net.bytebuddy.utility.JavaModule module, boolean loaded, net.bytebuddy.dynamic.DynamicType dynamicType) {
                var methods = new java.util.HashMap<String,Integer>();
                for(var method:type.getDeclaredMethods()) if(method.isMethod()&&!method.isAbstract()&&!method.isNative()) methods.merge(method.getName(),1,Integer::sum);
                ProbeApplicationStatus.transformed(type.getName(),methods);
            }
            @Override public void onError(String typeName,ClassLoader loader,net.bytebuddy.utility.JavaModule module,boolean loaded,Throwable error){ProbeApplicationStatus.failed(typeName);}
        };
        ab=ab.with(new AgentBuilder.Listener.Compound(applicationProof,verbose?AgentBuilder.Listener.StreamWriting.toSystemError():AgentBuilder.Listener.NoOp.INSTANCE));

        // Modo 1 — probes explícitos: fotografa SEMPRE (entrada/saída/erro) os
        // métodos classe#metodo configurados.
        if (probes != null && !probes.isEmpty()) {
            final List<Probe> ps = probes;
            Set<String> classNames = new LinkedHashSet<>();
            for (Probe p : ps) classNames.add(p.className);
            ab = ab.type(ElementMatchers.namedOneOf(classNames.toArray(new String[0])))
                    .transform((builder, type, cl, mod, pd) -> {
                        List<String> methods = new ArrayList<>();
                        for (Probe p : ps) {
                            if (p.className.equals(type.getName())&&p.line==0) methods.add(p.methodName);
                        }
                        var lines=ps.stream().filter(p->p.className.equals(type.getName())&&p.line>0).toList();
                        if(!methods.isEmpty())builder=builder.visit(Advice.to(CaptureAdvice.class).on(ElementMatchers.namedOneOf(methods.toArray(new String[0]))));
                        if(!lines.isEmpty())builder=builder.visit(SourceLineVisitor.wrapper(type.getName(),cl,lines));
                        return builder;
                    });
        }

        // Modo 2 — Exception Replay: instrumenta todos os métodos dos pacotes
        // configurados, mas só fotografa quando ALGO QUEBRA. Exclui o próprio
        // pacote do plugin (anti-loop).
        if (excPrefixes != null && !excPrefixes.isEmpty()) {
            ElementMatcher.Junction<TypeDescription> prefixMatch = ElementMatchers.none();
            for (String pfx : excPrefixes) prefixMatch = prefixMatch.or(ElementMatchers.nameStartsWith(pfx));
            ElementMatcher.Junction<TypeDescription> excTypes = prefixMatch.and(
                    ElementMatchers.not(ElementMatchers.nameStartsWith("system.monitoring.debugger")));
            ab = ab.type(excTypes)
                    .transform((builder, type, cl, mod, pd) ->
                            builder.visit(Advice.to(ExceptionAdvice.class).on(
                                    ElementMatchers.isMethod()
                                            .and(ElementMatchers.not(ElementMatchers.isAbstract()))
                                            .and(ElementMatchers.not(ElementMatchers.isNative()))
                                            .and(ElementMatchers.not(ElementMatchers.isSynthetic())))));
        }

        return ab.installOn(inst);
    }

    private static List<String> parsePrefixes(String spec) {
        List<String> out = new ArrayList<>();
        if (spec == null) return out;
        for (String s : spec.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private static long parseLong(String s, long def) {
        try { return s == null ? def : Long.parseLong(s.trim()); }
        catch (Exception e) { return def; }
    }

    private static String firstNonBlank(String... vs) {
        for (String v : vs) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }
}
