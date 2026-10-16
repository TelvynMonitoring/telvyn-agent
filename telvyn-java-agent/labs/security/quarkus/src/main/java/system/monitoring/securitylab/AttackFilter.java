package system.monitoring.securitylab;

import io.opentelemetry.context.Scope;

import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;
import org.jboss.resteasy.reactive.server.ServerResponseFilter;

/** Laboratory tracing only; detection comes from the installed application integration. */
@ApplicationScoped
@io.quarkus.runtime.Startup
public class AttackFilter {

    private SdkTracerProvider provider;
    private Tracer tracer;

    private static final String SPAN=AttackFilter.class.getName()+".span";

    @PostConstruct void start(){

        var exporter=OtlpHttpSpanExporter.builder().setEndpoint("http://telvyn-apm-validation-agent:4318/v1/traces").build();
        provider=SdkTracerProvider.builder().setResource(Resource.create(Attributes.builder()
            .put("service.name",System.getenv("TELVYN_SERVICE"))
            .put("deployment.environment.name",System.getenv("TELVYN_ENV"))
            .put("service.version",System.getenv("TELVYN_VERSION")).build()))
            .addSpanProcessor(SimpleSpanProcessor.create(exporter)).build();
        tracer=OpenTelemetrySdk.builder().setTracerProvider(provider).build().getTracer("security-quarkus-lab");
    }

    @ServerRequestFilter(priority=1000)
    public void inspect(ContainerRequestContext request){
        String route=request.getUriInfo().getRequestUri().getPath();
        if(!"GET".equals(request.getMethod())||!("/security-lab/search".equals(route)||"/security-lab/items".equals(route)||"/security-lab/orm".equals(route)))return;
        var span=tracer.spanBuilder("GET "+route).setSpanKind(SpanKind.SERVER)
            .setAttribute("http.route",route).startSpan();
        request.setProperty(SPAN,span);
        request.setProperty(SPAN+".scope",span.makeCurrent());
    }

    @ServerResponseFilter
    public void finish(ContainerRequestContext request,ContainerResponseContext response){
        if(request.getProperty(SPAN+".scope") instanceof Scope scope)scope.close();
        if(request.getProperty(SPAN) instanceof Span span){span.setAttribute("http.response.status_code",response.getStatus());span.end();}
    }

    @PreDestroy void stop(){if(provider!=null)provider.close();}
}
