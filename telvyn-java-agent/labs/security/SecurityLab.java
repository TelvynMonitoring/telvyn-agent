package system.monitoring.debugger;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;

/** Manual HTTP laboratory. No request headers, bodies or raw query enter telemetry. */
public final class SecurityLab {
    public static void main(String[] args)throws Exception {
        if(!"security-lab".equals(ProbeMetricSink.environment()))throw new IllegalStateException("security-lab environment required");
        boolean enabled=Boolean.getBoolean("telvyn.security.lab.enabled");
        var detector=new LocalAttackDetection();
        var reporter=new LocalAttackReporter();
        var exporter=OtlpHttpSpanExporter.builder().setEndpoint("http://telvyn-apm-validation-agent:4318/v1/traces").build();
        var provider=SdkTracerProvider.builder().setResource(Resource.create(Attributes.builder().put("service.name",SnapshotSink.service()).put("deployment.environment.name","security-lab").put("service.version",ProbeMetricSink.version()).build())).addSpanProcessor(SimpleSpanProcessor.create(exporter)).build();
        var tracer=OpenTelemetrySdk.builder().setTracerProvider(provider).build().getTracer("security-lab");
        var server=HttpServer.create(new InetSocketAddress(8089),0);
        server.createContext("/security-lab/search",exchange->{
            if(!"GET".equals(exchange.getRequestMethod())||!"/security-lab/search".equals(exchange.getRequestURI().getPath())){exchange.sendResponseHeaders(404,-1);exchange.close();return;}
            var span=tracer.spanBuilder("GET /security-lab/search").setSpanKind(SpanKind.SERVER).setAttribute("http.route","/security-lab/search").startSpan();
            String outcome="error";boolean queued=true;
            try {
                var result=detector.inspectSearchRequest(enabled,enabled?exchange.getRequestURI().getRawQuery():null);
                outcome=result.outcome();
                queued=reporter.report(result,span.getSpanContext().getTraceId(),span.getSpanContext().getSpanId());
            }catch(Exception failed){outcome="error";queued=false;}
            finally {
                span.setAttribute("http.response.status_code",200);span.end();
                byte[] body=("{\"request_completed\":true,\"blocked\":false,\"analysis\":\""+outcome+"\",\"report_queued\":"+queued+"}").getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(200,body.length);try(var output=exchange.getResponseBody()){output.write(body);}exchange.close();
            }
        });
        server.start();System.out.println("Local security laboratory ready; detection="+enabled);
    }
}
