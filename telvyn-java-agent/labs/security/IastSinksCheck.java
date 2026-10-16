package system.monitoring.securitylab;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import system.monitoring.debugger.IastRuntime;
import java.io.File;
import java.net.URI;
import java.net.URL;
import java.nio.file.Paths;
import java.lang.reflect.Proxy;
import java.security.MessageDigest;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.script.ScriptEngine;
import org.bson.Document;
import org.springframework.expression.ExpressionParser;

/**
 * Focused diagnostic for the inputs and sinks beyond SQL; run with assertions and the explicitly scoped Javaagent.
 * Nothing is executed or written: commands name a program that does not exist, files and hosts do not exist, URLs are only built.
 */
public class IastSinksCheck {
    // Interfaces that only record nothing: the call site is what the agent inspects, and no script, expression or response is really processed.
    static final HttpServletResponse RESPONSE = (HttpServletResponse) Proxy.newProxyInstance(IastSinksCheck.class.getClassLoader(), new Class<?>[] {HttpServletResponse.class}, (proxy, method, arguments) -> null);
    static final ScriptEngine ENGINE = (ScriptEngine) Proxy.newProxyInstance(IastSinksCheck.class.getClassLoader(), new Class<?>[] {ScriptEngine.class}, (proxy, method, arguments) -> null);
    static final ExpressionParser PARSER = (ExpressionParser) Proxy.newProxyInstance(IastSinksCheck.class.getClassLoader(), new Class<?>[] {ExpressionParser.class}, (proxy, method, arguments) -> null);
    @GET public static String response(@QueryParam("url") String url, @HeaderParam("X-Name") String name) throws Exception {
        RESPONSE.sendRedirect(url);
        RESPONSE.setHeader("X-Echo", name);
        RESPONSE.addHeader("X-Static", "constant");
        return "done";
    }
    @GET public static String code(@QueryParam("expr") String expr) throws Exception {
        ENGINE.eval(expr);
        PARSER.parseExpression("#{" + expr + "}");
        ENGINE.eval("1 + 1");
        return "done";
    }
    // org.bson.Document here is the stand-in in labs/security/stubs: same name and same parse signature as the MongoDB driver, which was not available.
    @GET public static String nosql(@QueryParam("filter") String filter) {
        Document.parse(filter);
        Document.parse("{\"status\": \"open\"}");
        return "done";
    }
    @GET public static String flaws(@QueryParam("x") String x) throws Exception {
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher.getInstance("AES/GCM/NoPadding");
        Cipher.getInstance("AES");
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        RESPONSE.addCookie(new Cookie("sid", "v"));
        var strong = new Cookie("sid2", "v");
        strong.setSecure(true); strong.setHttpOnly(true); strong.setAttribute("SameSite", "Lax");
        RESPONSE.addCookie(strong);
        var removal = new Cookie("old", "");
        removal.setMaxAge(0);
        RESPONSE.addCookie(removal);
        return "done" + x.length();
    }
    @GET public static String command(@QueryParam("cmd") String cmd) {
        try { Runtime.getRuntime().exec("telvyn-no-such-command-" + cmd); } catch (java.io.IOException expected) { }
        new ProcessBuilder("telvyn-no-such-command", cmd);
        return "done";
    }
    @GET public static String file(@PathParam("id") String id) {
        new File("/telvyn-nonexistent/" + id);
        Paths.get("/telvyn-nonexistent", id);
        try { new java.io.FileInputStream("/telvyn-nonexistent/" + id); } catch (java.io.FileNotFoundException expected) { }
        return "done";
    }
    @GET public static String url(@HeaderParam("X-Target") String host) throws Exception {
        URI.create("http://" + host + "/");
        new URL("http://" + host);
        return "done";
    }
    @GET public static String cookie(@CookieParam("sid") String sid) {
        new File("/telvyn-nonexistent/" + sid);
        return "done";
    }
    // Every call below keeps the origin through a different String or StringBuilder operation.
    @GET public static String propagation(@QueryParam("name") String name) {
        new File(new StringBuilder("/telvyn-nonexistent/").append(name).toString());
        new File("/telvyn-nonexistent/" + name.substring(1));
        new File("/telvyn-nonexistent/" + name.toUpperCase());
        new File("/telvyn-nonexistent/" + name.strip());
        new File("/telvyn-nonexistent/".concat(name.replace("a", "b")));
        return "done";
    }
    @GET public static String safe(@QueryParam("name") String name) {
        new File("/telvyn-nonexistent/constant");
        Paths.get("/telvyn-nonexistent", "constant");
        new File("/telvyn-nonexistent/" + new String("other"));
        URI.create("http://example.invalid/");
        return "done:" + name.length();
    }
    // The same call site runs twice in one request: one finding, not two.
    @GET public static String repeated(@QueryParam("name") String name) {
        for (int i = 0; i < 2; i++) new File("/telvyn-nonexistent/" + name);
        return "done";
    }
    static void expect(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    public static void main(String[] args) throws Exception {
        var findings = new ArrayList<IastRuntime.Finding>();
        IastRuntime.configureSources(method -> true);
        IastRuntime.configure(findings::add);
        String token = "tainted-token-7f3a";

        command(new String(token));
        expect(findings.size() == 2, "Runtime.exec and ProcessBuilder must each report once: " + findings.size());
        expect(findings.stream().allMatch(f -> "COMMAND_INJECTION".equals(f.ruleId()) && "query:cmd".equals(f.source())), "command class and query source");
        expect(findings.stream().anyMatch(f -> f.sink() != null && f.sink().contains("Runtime.exec")), "sink names Runtime.exec");
        expect(findings.stream().allMatch(f -> "iast-q-jvm-sinks-1".equals(f.rulesVersion()) && f.sql() == null), "rule set and no SQL text");
        findings.clear();

        file(new String(token));
        expect(findings.size() == 3, "File, Paths.get and FileInputStream must each report: " + findings.size());
        expect(findings.stream().allMatch(f -> "PATH_TRAVERSAL".equals(f.ruleId()) && "path:id".equals(f.source())), "path class and route source");
        findings.clear();

        url(new String(token));
        expect(findings.size() == 2, "URI.create and new URL must each report: " + findings.size());
        expect(findings.stream().allMatch(f -> "SSRF".equals(f.ruleId()) && "header:X-Target".equals(f.source())), "ssrf class and header source");
        findings.clear();

        cookie(new String(token));
        expect(findings.size() == 1 && "cookie:sid".equals(findings.get(0).source()), "cookie source");
        findings.clear();

        propagation(new String(token));
        expect(findings.size() == 5, "StringBuilder, substring, toUpperCase, strip and replace must keep the origin: " + findings.size());
        expect(findings.stream().allMatch(f -> "query:name".equals(f.source())), "origin kept through propagation");
        findings.clear();

        response(new String(token), new String(token));
        expect(findings.size() == 2, "redirect and header must each report once: " + findings.size());
        expect(findings.stream().anyMatch(f -> "UNVALIDATED_REDIRECT".equals(f.ruleId()) && "query:url".equals(f.source())), "redirect class and query source");
        expect(findings.stream().anyMatch(f -> "HEADER_INJECTION".equals(f.ruleId()) && "header:X-Name".equals(f.source())), "header class and header source");
        findings.clear();

        code(new String(token));
        expect(findings.size() == 2, "script eval and expression parser report; the constant script does not: " + findings.size());
        expect(findings.stream().allMatch(f -> "CODE_INJECTION".equals(f.ruleId()) && "query:expr".equals(f.source())), "code class and query source");
        findings.clear();

        nosql(new String(token));
        expect(findings.size() == 1 && "NOSQL_INJECTION".equals(findings.get(0).ruleId()) && "query:filter".equals(findings.get(0).source()), "document parsed from request text reports once, the constant document does not: " + findings.size());
        findings.clear();

        flaws(new String(token));
        expect(findings.size() == 6, "MD5, two ciphers and three cookie flaws, nothing else: " + findings.size());
        expect(findings.stream().allMatch(f -> "iast-jvm-flaws-1".equals(f.rulesVersion()) && f.source() == null && f.sql() == null), "flaws carry no input and no SQL");
        expect(findings.stream().filter(f -> "WEAK_HASH".equals(f.ruleId())).count() == 1, "one weak hash");
        expect(findings.stream().filter(f -> "WEAK_CIPHER".equals(f.ruleId())).count() == 2, "DES/ECB and the bare AES");
        for (var rule : java.util.List.of("INSECURE_COOKIE", "NO_HTTPONLY_COOKIE", "NO_SAMESITE_COOKIE"))
            expect(findings.stream().filter(f -> rule.equals(f.ruleId())).count() == 1, "one " + rule + ", and neither the protected nor the removal cookie");
        findings.clear();

        safe(new String(token));
        expect(findings.isEmpty(), "constants and unrelated strings are not findings: " + findings.size());
        repeated(new String(token));
        expect(findings.size() == 1, "same place, same request: one finding: " + findings.size());
        findings.clear();

        // The agent never sends the value, anywhere in a finding.
        command(new String(token));
        file(new String(token));
        for (var f : findings) {
            String all = f.method() + f.sink() + f.sql() + f.stack() + f.ruleId() + f.source() + f.rulesVersion();
            expect(!all.contains(token), "a finding must not contain the input value");
            expect(f.stack() != null && !f.stack().isEmpty() && f.stack().get(0).contains("IastSinksCheck"), "stack starts at the application frame");
            expect(f.line() != null && f.line() > 0, "finding names the line");
        }
        findings.clear();

        // Outside any selected request there is nothing to report, including the flaws that need no input.
        IastRuntime.configureSources(method -> false);
        command(new String(token));
        flaws(new String(token));
        expect(findings.isEmpty(), "an unselected route reports nothing");
        IastRuntime.configure(null);
        System.out.println("IAST sinks: command, path (File, Paths, FileInputStream), ssrf (URI, URL), sources (query, path, header, cookie), propagation (StringBuilder, substring, toUpperCase, strip, replace), code, nosql, redirect, header, weak hash, weak cipher, cookies, constants, repetition, no value in findings and unselected route passed");
    }
}
