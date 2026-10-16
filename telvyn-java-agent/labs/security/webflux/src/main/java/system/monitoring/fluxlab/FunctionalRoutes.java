package system.monitoring.fluxlab;
import org.springframework.context.annotation.*;
import org.springframework.web.reactive.function.server.*;
import reactor.core.publisher.Mono;
/** Normal functional routing; security is provided by the Javaagent. */
@Configuration
public class FunctionalRoutes{
 private final FluxLab lab;
 public FunctionalRoutes(FluxLab lab){this.lab=lab;}
 @Bean RouterFunction<ServerResponse> functions(){return RouterFunctions.route()
  .GET("/flux-lab/function",this::search)
  .POST("/flux-lab/function",this::search)
  .path("/flux-lab/nested",builder->builder.GET("/{name}",this::search))
  .GET("/flux-lab/function-outside",this::search).build();}
 private Mono<ServerResponse> search(ServerRequest request){
  String q="map".equals(request.queryParam("source").orElse(""))?request.queryParams().getFirst("q"):request.queryParam("q").orElse("");
  String mode=request.queryParam("mode").orElse("constant");
  String api=request.queryParam("api").orElse("client");
  if("handler-error".equals(mode))return Mono.<ServerResponse>error(new IllegalStateException("controlled functional error")).onErrorResume(error->ServerResponse.status(500).bodyValue("controlled_error"));
  if("empty".equals(mode))return Mono.empty();
  Mono<String> body=lab.r2dbc(q,mode,api).onErrorReturn("database_rejected");
  if("slow".equals(request.queryParam("pace").orElse("")))body=Mono.delay(java.time.Duration.ofSeconds(2)).then(body);
  return ServerResponse.ok().body(body,String.class);
 }
}
