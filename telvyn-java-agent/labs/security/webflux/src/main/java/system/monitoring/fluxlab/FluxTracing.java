package system.monitoring.fluxlab;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.*;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.*;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.*;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.micrometer.context.ContextRegistry;
import org.springframework.stereotype.Component;
import org.springframework.web.server.*;
import reactor.core.publisher.*;
/** Actual lab tracing using ordinary Micrometer/OTel context propagation. */
@Component
public class FluxTracing implements WebFilter {
 private final ThreadLocal<Scope> scopes=new ThreadLocal<>();
 private final SdkTracerProvider provider=provider();
 private static SdkTracerProvider provider(){
  var builder=SdkTracerProvider.builder().setResource(Resource.create(Attributes.builder().put("service.name",System.getenv("TELVYN_SERVICE")).put("deployment.environment.name",System.getenv("TELVYN_ENV")).put("service.version",System.getenv("TELVYN_VERSION")).build()));
  if(!"false".equals(System.getProperty("lab.tracing.enabled")))builder.addSpanProcessor(SimpleSpanProcessor.create(OtlpHttpSpanExporter.builder().setEndpoint("http://telvyn-apm-validation-agent:4318/v1/traces").build()));
  return builder.build();
 }
 private final io.opentelemetry.api.trace.Tracer tracer=OpenTelemetrySdk.builder().setTracerProvider(provider).build().getTracer("spring-webflux-lab");
 public FluxTracing(){if("false".equals(System.getProperty("lab.tracing.enabled")))return;ContextRegistry.getInstance().registerThreadLocalAccessor("lab.otel.context",Context::current,c->{reset();scopes.set(c.makeCurrent());},this::reset);Hooks.enableAutomaticContextPropagation();}
 private void reset(){var scope=scopes.get();if(scope!=null)scope.close();scopes.remove();}
 public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain){
  if("false".equals(System.getProperty("lab.tracing.enabled")))return chain.filter(exchange);
  String path=exchange.getRequest().getPath().value();if(!java.util.Set.of("/flux-lab/search","/flux-lab/stream","/flux-lab/r2dbc","/flux-lab/function","/flux-lab/nested/one","/flux-lab/function-outside","/flux-lab/data","/flux-lab/reuse").contains(path))return chain.filter(exchange);
  var span=tracer.spanBuilder(exchange.getRequest().getMethod()+" "+path).setSpanKind(SpanKind.SERVER).setAttribute("http.route",path).startSpan();
  return chain.filter(exchange).contextWrite(ctx->ctx.put("lab.otel.context",Context.root().with(span))).doFinally(signal->{var status=exchange.getResponse().getStatusCode();if(status!=null)span.setAttribute("http.response.status_code",status.value());span.end();});
 }
 @jakarta.annotation.PreDestroy void stop(){provider.close();}
}
