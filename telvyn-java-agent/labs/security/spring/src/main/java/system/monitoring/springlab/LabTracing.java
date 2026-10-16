package system.monitoring.springlab;

import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.Set;

/** Lab tracing only: production security reuses the application's valid tracing context. */
@Component
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(name="lab.tracing.enabled",havingValue="true",matchIfMissing=true)
public class LabTracing extends OncePerRequestFilter {
 private final SdkTracerProvider provider=SdkTracerProvider.builder().setResource(Resource.create(Attributes.builder()
  .put("service.name",System.getenv("TELVYN_SERVICE")).put("deployment.environment.name",System.getenv("TELVYN_ENV"))
  .put("service.version",System.getenv("TELVYN_VERSION")).build()))
  .addSpanProcessor(SimpleSpanProcessor.create(OtlpHttpSpanExporter.builder().setEndpoint("http://telvyn-apm-validation-agent:4318/v1/traces").build())).build();
 private final io.opentelemetry.api.trace.Tracer tracer=OpenTelemetrySdk.builder().setTracerProvider(provider).build().getTracer("security-spring-lab");
 @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws ServletException,IOException {
  String route=request.getRequestURI();
  if(!Set.of("/spring-lab/search","/spring-lab/items","/spring-lab/outside","/spring-lab/jpa","/spring-lab/callable","/spring-lab/future","/spring-lab/deferred","/spring-lab/annotated","/spring-lab/task","/spring-lab/executor").contains(route)){chain.doFilter(request,response);return;}
  var span=tracer.spanBuilder(request.getMethod()+" "+route).setSpanKind(SpanKind.SERVER).setAttribute("http.route",route).startSpan();
  try(var scope=span.makeCurrent()){chain.doFilter(request,response);}finally{
   if(request.isAsyncStarted())request.getAsyncContext().addListener(new AsyncListener(){
    public void onComplete(AsyncEvent event){span.setAttribute("http.response.status_code",response.getStatus());span.end();}
    public void onError(AsyncEvent event){span.end();}public void onTimeout(AsyncEvent event){span.end();}public void onStartAsync(AsyncEvent event){}
   });else{span.setAttribute("http.response.status_code",response.getStatus());span.end();}
  }
 }
 @jakarta.annotation.PreDestroy void stop(){provider.close();}
}
