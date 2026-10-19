package system.monitoring.debugger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runtime SCA: as bibliotecas que a aplicação carregou de fato. Para cada jar de onde a JVM carregou
 * uma classe, o groupId, artifactId e versão do {@code META-INF/maven/.../pom.properties} (também dentro dos jars
 * aninhados do Spring Boot), enviados ao coletor; o casamento com os advisories roda no backend. Jar sem
 * pom.properties (Gradle, Ant): nome e versão deduzidos do manifest e do nome do arquivo, e o SHA-1 do
 * jar, que o backend resolve no Maven Central. Liga com
 * {@code -Dtelvyn.sca.enabled=true} ou {@code TELVYN_SCA_ENABLED=true}. Nenhuma classe é alterada.
 */
final class ScaLibraries implements ClassFileTransformer {
    static final long FIRST_MS = 15_000, EVERY_MS = 60_000, RESEND_MS = 12 * 3600_000L;
    static final int BATCH = 400;
    private static final Pattern FILE = Pattern.compile("^(.+?)(?:-([0-9][^-]+(?:-\\w+)?))?\\.jar$");
    private static final Pattern VERSION = Pattern.compile("[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}");
    private static final Map<ProtectionDomain, Boolean> DOMAINS = Collections.synchronizedMap(new WeakHashMap<>());
    private static final Queue<String> PENDING = new ConcurrentLinkedQueue<>();
    private static final Set<String> LOCATIONS = new HashSet<>();
    // groupId:artifactId@version -> sent
    private static final Set<String> KNOWN = new LinkedHashSet<>();
    private static final String OWN = ScaLibraries.class.getProtectionDomain().getCodeSource() == null ? "" : String.valueOf(ScaLibraries.class.getProtectionDomain().getCodeSource().getLocation());
    private static volatile LocalAttackReporter reporter;

    private ScaLibraries() {}

    static boolean enabled() {
        return Boolean.parseBoolean(System.getProperty("telvyn.sca.enabled", System.getenv().getOrDefault("TELVYN_SCA_ENABLED", "false")));
    }

    static void install(Instrumentation instrumentation) {
        if (!enabled()) return;
        instrumentation.addTransformer(new ScaLibraries(), false);
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) seen(loaded.getProtectionDomain());
        Thread worker = new Thread(ScaLibraries::run, "telvyn-sca");
        worker.setDaemon(true);
        worker.start();
    }

    @Override
    public byte[] transform(ClassLoader loader, String name, Class<?> redefined, ProtectionDomain domain, byte[] bytes) {
        seen(domain);
        return null;
    }

    private static void seen(ProtectionDomain domain) {
        if (domain == null || DOMAINS.containsKey(domain)) return;
        DOMAINS.put(domain, Boolean.TRUE);
        var source = domain.getCodeSource();
        if (source != null && source.getLocation() != null) PENDING.add(source.getLocation().toString());
    }

    private static void run() {
        long resend = System.currentTimeMillis() + RESEND_MS;
        try {
            Thread.sleep(FIRST_MS);
            while (!Thread.currentThread().isInterrupted()) {
                List<String[]> found = new ArrayList<>();
                for (String location; (location = PENDING.poll()) != null; ) {
                    if (location.equals(OWN) || !LOCATIONS.add(location)) continue;
                    for (String[] library : resolve(location)) if (KNOWN.add(library[0] + "@" + library[1] + (library.length > 2 ? "#" + library[2] : ""))) found.add(library);
                }
                // Visto de novo: a lista inteira volta de tempos em tempos, para o achado seguir ativo enquanto o serviço roda.
                if (System.currentTimeMillis() >= resend) {
                    resend = System.currentTimeMillis() + RESEND_MS;
                    found.clear();
                    for (String key : KNOWN) {
                        int at = key.lastIndexOf('@'), hash = key.indexOf('#', at);
                        found.add(hash < 0 ? new String[]{key.substring(0, at), key.substring(at + 1)} : new String[]{key.substring(0, at), key.substring(at + 1, hash), key.substring(hash + 1)});
                    }
                }
                for (int from = 0; from < found.size(); from += BATCH) reporter().reportLibraries("Maven", found.subList(from, Math.min(found.size(), from + BATCH)));
                Thread.sleep(EVERY_MS);
            }
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException | LinkageError failure) {
            LocalAttackReporter.reportLoss("SCA libraries unavailable");
        }
    }

    private static LocalAttackReporter reporter() {
        var current = reporter;
        if (current != null) return current;
        synchronized (ScaLibraries.class) {
            if (reporter == null) reporter = new LocalAttackReporter(Collector.url() + "/v1/security/libraries", SnapshotSink.service(), SnapshotSink.host(), ProbeMetricSink.environment(), ProbeMetricSink.version(), null);
            return reporter;
        }
    }

    /** Bibliotecas de um local de código: jar comum, jar dentro de outro jar (Spring Boot) ou diretório (ignorado). */
    static List<String[]> resolve(String location) {
        try {
            if (location.startsWith("file:")) {
                Path path = Paths.get(new java.net.URI(location));
                if (!Files.isRegularFile(path)) return List.of();
                try (var jar = new JarFile(path.toFile())) {
                    var found = libraries(jar);
                    if (!found.isEmpty()) return found;
                    try (InputStream input = Files.newInputStream(path)) { return fallback(jar.getManifest() == null ? null : jar.getManifest().getMainAttributes(), path.getFileName().toString(), input); }
                }
            }
            if (location.startsWith("jar:")) {
                // jar:file:/app.jar!/BOOT-INF/lib/x.jar!/ (Spring Boot até 3.1) e jar:nested:/app.jar/!BOOT-INF/lib/x.jar!/ (3.2+).
                String rest = location.substring(4);
                boolean nested = rest.startsWith("nested:");
                String outer, inner;
                if (nested) {
                    int split = rest.indexOf("/!");
                    if (split < 0) return List.of();
                    outer = rest.substring("nested:".length(), split);
                    inner = rest.substring(split + 2);
                } else {
                    int split = rest.indexOf("!/");
                    if (split < 0) return List.of();
                    outer = rest.substring(rest.startsWith("file:") ? 5 : 0, split);
                    inner = rest.substring(split + 2);
                }
                if (inner.endsWith("!/")) inner = inner.substring(0, inner.length() - 2);
                Path path = Paths.get(java.net.URLDecoder.decode(outer, java.nio.charset.StandardCharsets.UTF_8));
                if (!Files.isRegularFile(path)) return List.of();
                try (var jar = new JarFile(path.toFile())) {
                    if (inner.isEmpty()) {
                        var found = libraries(jar);
                        if (!found.isEmpty()) return found;
                        try (InputStream input = Files.newInputStream(path)) { return fallback(jar.getManifest() == null ? null : jar.getManifest().getMainAttributes(), path.getFileName().toString(), input); }
                    }
                    var entry = jar.getJarEntry(inner);
                    if (entry == null || entry.getSize() > 256L * 1024 * 1024) return List.of();
                    List<String[]> found;
                    Attributes manifest;
                    try (InputStream input = jar.getInputStream(entry); var nestedJar = new JarInputStream(input)) {
                        found = libraries(nestedJar);
                        manifest = nestedJar.getManifest() == null ? null : nestedJar.getManifest().getMainAttributes();
                    }
                    if (!found.isEmpty()) return found;
                    try (InputStream input = jar.getInputStream(entry)) { return fallback(manifest, inner, input); }
                }
            }
        } catch (IOException | RuntimeException | java.net.URISyntaxException unreadable) {
            LocalAttackReporter.reportLoss("SCA library unreadable");
        }
        return List.of();
    }

    private static List<String[]> libraries(JarFile jar) throws IOException {
        List<String[]> out = new ArrayList<>();
        for (var entries = jar.entries(); entries.hasMoreElements(); ) {
            var entry = entries.nextElement();
            if (pom(entry.getName())) try (var input = jar.getInputStream(entry)) { add(out, input); }
        }
        return out;
    }

    private static List<String[]> libraries(JarInputStream jar) throws IOException {
        List<String[]> out = new ArrayList<>();
        for (var entry = jar.getNextJarEntry(); entry != null; entry = jar.getNextJarEntry())
            if (pom(entry.getName())) add(out, new ByteArrayInputStream(jar.readNBytes(64 * 1024)));
        return out;
    }

    /**
     * Jar sem pom.properties: artifactId do Bundle-Name ou Implementation-Title (ou do nome do arquivo),
     * versão do manifest ou do nome do arquivo, groupId do Bundle-SymbolicName quando ele é "groupId.artifactId", e o
     * SHA-1 do jar para o backend identificar o artefato no Maven Central.
     */
    static List<String[]> fallback(Attributes manifest, String source, InputStream input) throws IOException {
        source = source.substring(source.lastIndexOf('/') + 1);
        String symbolic = null, bundleName = null, bundleVersion = null, title = null, implementation = null;
        if (manifest != null) {
            symbolic = manifest.getValue("Bundle-SymbolicName");
            if (symbolic != null) symbolic = symbolic.split(";", 2)[0].trim();
            bundleName = manifest.getValue("Bundle-Name");
            bundleVersion = manifest.getValue("Bundle-Version");
            title = manifest.getValue("Implementation-Title");
            implementation = manifest.getValue("Implementation-Version");
        }
        Matcher file = FILE.matcher(source);
        String fileArtifact = file.matches() ? file.group(1) : source, fileVersion = file.matches() ? file.group(2) : null;
        String artifact = artifactId(bundleName) ? bundleName : artifactId(title) ? title : fileArtifact;
        String version = bundleVersion != null && bundleVersion.equals(implementation) ? bundleVersion
            : fileVersion != null && !fileVersion.isEmpty() ? fileVersion : bundleVersion != null ? bundleVersion : implementation;
        String group = null;
        if (symbolic != null) {
            group = groupId(symbolic, fileArtifact);
            if (group == null) group = groupId(symbolic, bundleName);
        }
        String name = group == null ? artifact : group + ":" + artifact;
        var digest = sha1(input);
        if (digest == null || version == null || !VERSION.matcher(version.trim()).matches() || !name.matches("(?:[A-Za-z0-9_.-]{1,255}:)?[A-Za-z0-9_.-]{1,255}")) return List.of();
        return List.<String[]>of(new String[]{name, version.trim(), digest});
    }

    private static boolean artifactId(String value) {
        return value != null && !value.isEmpty() && !value.contains(" ") && !value.contains(".") && value.toLowerCase(Locale.ROOT).equals(value);
    }

    // Bundle-SymbolicName "groupId.artifactId": o groupId é o que vem antes, se tiver ponto e mais de 5 caracteres.
    private static String groupId(String symbolic, String artifact) {
        if (artifact == null || !symbolic.endsWith("." + artifact)) return null;
        String group = symbolic.substring(0, symbolic.length() - artifact.length() - 1);
        return group.contains(".") && group.length() > 5 && !group.contains(" ") && group.toLowerCase(Locale.ROOT).equals(group) ? group : null;
    }

    private static String sha1(InputStream input) throws IOException {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-1");
            byte[] buffer = new byte[64 * 1024];
            for (int read; (read = input.read(buffer)) > 0; ) digest.update(buffer, 0, read);
            return String.format("%040x", new java.math.BigInteger(1, digest.digest()));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            return null;
        }
    }

    private static boolean pom(String name) {
        return name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties");
    }

    // Um jar sombreado (shaded) traz o pom.properties de cada biblioteca embutida: todas são código presente.
    private static void add(List<String[]> out, InputStream input) throws IOException {
        var properties = new Properties();
        properties.load(input);
        String group = properties.getProperty("groupId"), artifact = properties.getProperty("artifactId"), version = properties.getProperty("version");
        if (group == null || artifact == null || version == null) return;
        String name = group.trim() + ":" + artifact.trim();
        version = version.trim();
        if (name.matches("[A-Za-z0-9_.-]{1,255}:[A-Za-z0-9_.-]{1,255}") && version.matches("[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}") && !version.contains("${"))
            out.add(new String[]{name, version});
    }
}
