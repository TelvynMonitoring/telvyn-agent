package system.monitoring.fluxlab;
import org.springframework.web.bind.annotation.*;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.*;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.*;
@RestController
public class DataQueries{
 private final DataPeople people;private final R2dbcEntityTemplate template;private final DatabaseClient client;
 public DataQueries(DataPeople people,R2dbcEntityTemplate template,DatabaseClient client){this.people=people;this.template=template;this.client=client;}
 @jakarta.annotation.PostConstruct void initialize(){client.sql("CREATE TABLE IF NOT EXISTS data_person(id BIGINT PRIMARY KEY,name VARCHAR(255))").then().block();}
 @GetMapping("/flux-lab/data") public Mono<String> search(@RequestParam("q")String q,@RequestParam("api")String api,@RequestParam("mode")String mode){
  return Mono.defer(()->{
   if("raise".equals(mode))return Mono.error(new IllegalStateException("controlled data error"));
   if("derived".equals(api))return people.findByName(q).then(Mono.just("completed"));
   if("declared".equals(api))return people.named(q).then(Mono.just("completed"));
   if("template".equals(api))return template.select(DataPerson.class).matching(Query.query(Criteria.where("name").is(q))).all().then(Mono.just("completed"));
   var query=template.getDatabaseClient().sql("parameterized".equals(mode)?"SELECT id,name FROM data_person WHERE name=:q":"constant".equals(mode)?"SELECT id,name FROM data_person":"SELECT id,name FROM data_person WHERE name='"+q.trim().toLowerCase()+"'");
   if("parameterized".equals(mode))query=query.bind("q",q);
   return query.fetch().all().then(Mono.just("completed"));
  }).subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic()).onErrorReturn("database_rejected");
 }
}
