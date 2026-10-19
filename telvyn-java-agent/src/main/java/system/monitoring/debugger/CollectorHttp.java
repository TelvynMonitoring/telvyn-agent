package system.monitoring.debugger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * HTTP/1.1 mínimo sobre socket para falar com o coletor. O cliente HTTP do JDK é instrumentado pelo agente
 * OpenTelemetry, que transformaria cada envio do agente em trace da aplicação; por isso o envio
 * não é rastreado.
 */
public final class CollectorHttp {
    public record Response(int status, String body) {}
    private static final int MAX_BODY = (1 << 20) + 1;

    private CollectorHttp() {}

    public static Response get(String url, int timeoutMs) throws IOException { return send("GET", url, null, timeoutMs); }
    public static Response post(String url, String json, int timeoutMs) throws IOException { return send("POST", url, json, timeoutMs); }

    static Response send(String method, String url, String json, int timeoutMs) throws IOException {
        URI uri = URI.create(url);
        boolean tls = "https".equals(uri.getScheme());
        if (!tls && !"http".equals(uri.getScheme()) || uri.getHost() == null) throw new IOException("invalid collector endpoint");
        int port = uri.getPort() > 0 ? uri.getPort() : tls ? 443 : 80;
        String target = (uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath()) + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        byte[] body = json == null ? new byte[0] : json.getBytes(StandardCharsets.UTF_8);
        try (Socket socket = open(uri.getHost(), port, tls, timeoutMs)) {
            OutputStream out = socket.getOutputStream();
            StringBuilder head = new StringBuilder(method).append(' ').append(target).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(uri.getHost()).append(uri.getPort() > 0 ? ":" + uri.getPort() : "").append("\r\n")
                    .append("Connection: close\r\nAccept: application/json\r\n");
            if (json != null) head.append("Content-Type: application/json\r\nContent-Length: ").append(body.length).append("\r\n");
            out.write(head.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
            return read(socket.getInputStream());
        }
    }

    private static Socket open(String host, int port, boolean tls, int timeoutMs) throws IOException {
        Socket plain = new Socket();
        plain.connect(new InetSocketAddress(host, port), timeoutMs);
        plain.setSoTimeout(timeoutMs);
        if (!tls) return plain;
        SSLSocket secure = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(plain, host, port, true);
        var parameters = secure.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        secure.setSSLParameters(parameters);
        secure.startHandshake();
        return secure;
    }

    private static Response read(InputStream in) throws IOException {
        String status = line(in);
        String[] parts = status.split(" ", 3);
        if (parts.length < 2 || !parts[0].startsWith("HTTP/1.")) throw new IOException("invalid collector response");
        int code = Integer.parseInt(parts[1]);
        long length = -1;
        boolean chunked = false;
        for (String header; !(header = line(in)).isEmpty(); ) {
            int colon = header.indexOf(':');
            if (colon < 0) continue;
            String name = header.substring(0, colon).trim(), value = header.substring(colon + 1).trim();
            if (name.equalsIgnoreCase("Content-Length")) length = Long.parseLong(value);
            if (name.equalsIgnoreCase("Transfer-Encoding") && value.toLowerCase().contains("chunked")) chunked = true;
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if (chunked) {
            for (long size; (size = Long.parseLong(line(in).split(";", 2)[0].trim(), 16)) > 0; ) {
                copy(in, body, size);
                line(in);
            }
        } else if (length >= 0) {
            copy(in, body, length);
        } else {
            copy(in, body, Long.MAX_VALUE);
        }
        return new Response(code, body.toString(StandardCharsets.UTF_8));
    }

    private static void copy(InputStream in, ByteArrayOutputStream body, long size) throws IOException {
        byte[] buffer = new byte[8192];
        for (long left = size; left > 0; ) {
            int read = in.read(buffer, 0, (int) Math.min(buffer.length, left));
            if (read < 0) {
                if (size == Long.MAX_VALUE) return;
                throw new IOException("truncated collector response");
            }
            if (body.size() + read > MAX_BODY) throw new IOException("collector response too large");
            body.write(buffer, 0, read);
            left -= read;
        }
    }

    private static String line(InputStream in) throws IOException {
        StringBuilder text = new StringBuilder();
        for (int c; (c = in.read()) != '\n'; ) {
            if (c < 0) throw new IOException("truncated collector response");
            if (c != '\r') text.append((char) c);
            if (text.length() > 8192) throw new IOException("collector header too long");
        }
        return text.toString();
    }
}
