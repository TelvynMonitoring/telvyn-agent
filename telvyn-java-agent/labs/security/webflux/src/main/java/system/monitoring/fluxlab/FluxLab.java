package system.monitoring.fluxlab;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.*;
import reactor.core.scheduler.Schedulers;
import java.sql.*;
@SpringBootApplication @RestController @RequestMapping("/flux-lab")
public class FluxLab {
 private final io.r2dbc.spi.ConnectionFactory connections;
 private final org.springframework.r2dbc.core.DatabaseClient client;
 public FluxLab(io.r2dbc.spi.ConnectionFactory connections,org.springframework.r2dbc.core.DatabaseClient client){this.connections=connections;this.client=client;}
 @GetMapping("/r2dbc") public Mono<String> r2dbc(@RequestParam("q")String q,@RequestParam("mode")String mode,@RequestParam("api")String api){
  return Mono.defer(()->{
   if("raise".equals(mode))return Mono.error(new IllegalStateException("controlled R2DBC error"));
   boolean bound="parameterized".equals(mode);
   if("spi".equals(api))return Mono.usingWhen(Mono.from(connections.create()),connection->{
    var statement=connection.createStatement(bound?"SELECT 1 WHERE $1 = 'sample'":"constant".equals(mode)?"SELECT 1":"SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'");
    if(bound)statement.bind(0,q);
    return Flux.from(statement.execute()).flatMap(result->result.map((row,metadata)->row.get(0,Integer.class))).then(Mono.just("completed"));
   },connection->Mono.from(connection.close()));
   org.springframework.r2dbc.core.DatabaseClient.GenericExecuteSpec query;
   if("prepared".equals(api))query=client.sql(new org.springframework.r2dbc.core.PreparedOperation<String>(){
    public String getSource(){return bound?"SELECT 1 WHERE $1 = 'sample'":"constant".equals(mode)?"SELECT 1":"SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'";}
    public String toQuery(){return getSource();}
    public void bindTo(org.springframework.r2dbc.core.binding.BindTarget target){if(bound)target.bind(0,q);}
   });
   else if("supplier".equals(api))query=client.sql(()->bound?"SELECT 1 WHERE :q = 'sample'":"constant".equals(mode)?"SELECT 1":"SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'");
   else query=client.sql(bound?"SELECT 1 WHERE :q = 'sample'":"constant".equals(mode)?"SELECT 1":"SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'");
   if(bound&&!"prepared".equals(api))query=query.bind("q",q);
   return query.fetch().all().then(Mono.just("completed"));
  }).subscribeOn(Schedulers.boundedElastic()).onErrorMap(error->new IllegalStateException("controlled R2DBC error"));
 }
 public static void main(String[] args){SpringApplication.run(FluxLab.class,args);}
 @GetMapping("/reuse") public Mono<String> reuse(@RequestParam("q")String q,@RequestParam("mode")String mode,@RequestParam("api")String api){
  var attempts=new java.util.concurrent.atomic.AtomicInteger();var queries=new java.util.concurrent.atomic.AtomicInteger();
  Mono<String> work=Mono.defer(()->{if(attempts.incrementAndGet()==1&&"retry".equals(api))return Mono.error(new IllegalStateException("controlled first attempt"));queries.incrementAndGet();return Mono.fromCallable(()->query(q,mode));}).subscribeOn(Schedulers.boundedElastic());
  if("retry".equals(api))return work.retry(1).map(result->result+" attempts="+attempts.get()+" queries="+queries.get());
  if("share".equals(api))work=work.cache();
  return Mono.zip(work,work).map(results->results.getT1()+" attempts="+attempts.get()+" queries="+queries.get());
 }
 @GetMapping("/search") public Mono<String> search(@RequestParam("q")String q,@RequestParam("mode")String mode){return Mono.fromCallable(()->query(q,mode)).subscribeOn(Schedulers.boundedElastic());}
 @GetMapping("/stream") public Flux<String> stream(@RequestParam("q")String q,@RequestParam("mode")String mode){return Flux.defer(()->Flux.just(query(q,mode))).subscribeOn(Schedulers.boundedElastic());}
 private String query(String q,String mode){
  if("raise".equals(mode))throw new IllegalStateException("controlled reactive error");
  try(var connection=DriverManager.getConnection("jdbc:h2:mem:flux")){
   if("parameterized".equals(mode)){try(var p=connection.prepareStatement("SELECT 1 WHERE ? = 'sample'")){p.setString(1,q);try(var r=p.executeQuery()){while(r.next())r.getInt(1);}}}
   else try(var s=connection.createStatement();var r=s.executeQuery("SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'")){while(r.next())r.getInt(1);}
   return "completed";
  }catch(SQLException rejected){return "database_rejected";}
 }
 @ExceptionHandler(IllegalStateException.class) @ResponseStatus(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR) public String failure(){return "controlled_error";}
}
