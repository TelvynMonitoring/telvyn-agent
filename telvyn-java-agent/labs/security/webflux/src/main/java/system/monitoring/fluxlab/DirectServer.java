package system.monitoring.fluxlab;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ApplicationArguments;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.*;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import reactor.netty.http.server.HttpServer;
@Component
public class DirectServer implements ApplicationRunner{
 private final FunctionalRoutes routes;private final FluxTracing tracing;
 private reactor.netty.DisposableServer server;
 public DirectServer(FunctionalRoutes routes,FluxTracing tracing){this.routes=routes;this.tracing=tracing;}
 public void run(ApplicationArguments args){server=HttpServer.create().port(8090).handle(new ReactorHttpHandlerAdapter(RouterFunctions.toHttpHandler(routes.functions(),HandlerStrategies.builder().webFilter(tracing).build()))).bindNow();}
 @jakarta.annotation.PreDestroy void stop(){if(server!=null)server.disposeNow();}
}
