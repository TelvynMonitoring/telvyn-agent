package system.monitoring.springlab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.sql.*;
import java.util.List;

@SpringBootApplication
@org.springframework.scheduling.annotation.EnableAsync
@RestController
@RequestMapping("/spring-lab")
public class SpringLab {
 private final JdbcTemplate jdbc;
 public SpringLab(JdbcTemplate jdbc){this.jdbc=jdbc;}
 @org.springframework.beans.factory.annotation.Autowired PersonRepository people;
 @org.springframework.beans.factory.annotation.Autowired PersonQueries queries;
 @org.springframework.beans.factory.annotation.Autowired AsyncQueries async;
 @GetMapping("/jpa") public List<Person> jpa(@RequestParam("q")String q,@RequestParam("mode")String mode){
  if("derived".equals(mode))return people.findByName(q);
  if("named".equals(mode))return people.named(q);
  return queries.search(q,mode);
 }
 @GetMapping("/callable") public java.util.concurrent.Callable<List<Integer>> callable(@RequestParam("q")String q,@RequestParam("mode")String mode){return ()->asyncQuery(q,mode);}
 @GetMapping("/future") public java.util.concurrent.CompletableFuture<List<Integer>> future(@RequestParam("q")String q,@RequestParam("mode")String mode){return java.util.concurrent.CompletableFuture.supplyAsync(()->q).thenApplyAsync(value->asyncQuery(value,mode));}
 @GetMapping("/annotated") public java.util.concurrent.CompletionStage<List<Integer>> annotated(@RequestParam("q")String q,@RequestParam("mode")String mode){return async.load(q,mode);}
 @GetMapping("/deferred") public org.springframework.web.context.request.async.DeferredResult<List<Integer>> deferred(@RequestParam("q")String q,@RequestParam("mode")String mode){
  var result=new org.springframework.web.context.request.async.DeferredResult<List<Integer>>(5000L);
  java.util.concurrent.CompletableFuture.runAsync(()->{try{result.setResult(asyncQuery(q,mode));}catch(RuntimeException error){result.setErrorResult(error);}});return result;
 }
 private List<Integer> asyncQuery(String q,String mode){
  if("raise".equals(mode))throw new IllegalStateException("controlled async exception");
  if("parameterized".equals(mode))return jdbc.queryForList("SELECT 1 WHERE ? = 'sample'",Integer.class,q);
  return jdbc.queryForList("SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'",Integer.class);
 }
 public static void main(String[] args){SpringApplication.run(SpringLab.class,args);}
 @GetMapping("/search")
 public String search(@RequestParam(name="q",required=false)String q,@RequestParam(name="mode",defaultValue="constant")String mode)throws SQLException{
  if("raise".equals(mode))throw new IllegalStateException("local controlled exception");
  try(var connection=jdbc.getDataSource().getConnection()){
   if("parameterized".equals(mode)){try(var p=connection.prepareStatement("SELECT 1 WHERE ? = 'sample'")){p.setString(1,q);try(var rows=p.executeQuery()){while(rows.next())rows.getInt(1);}}}
   else if("concat".equals(mode)&&q!=null){try(var s=connection.createStatement();var rows=s.executeQuery("SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'")){while(rows.next())rows.getInt(1);}}
   else {try(var s=connection.createStatement();var rows=s.executeQuery("SELECT 1")){rows.next();}}
  }catch(SQLException rejected){return "{\"request_completed\":true,\"database_rejected\":true}";}
  return "{\"request_completed\":true}";
 }
 @GetMapping("/items")
 public List<Integer> items(@RequestParam("q")String q,@RequestParam("mode")String mode){
  if("parameterized".equals(mode))return jdbc.queryForList("SELECT 1 WHERE ? = 'sample'",Integer.class,q);
  return jdbc.queryForList("SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'",Integer.class);
 }
 @GetMapping("/outside") public String outside(@RequestParam("q")String q){return "{\"request_completed\":true}";}
 @PostMapping("/search") public String post(){return "{\"request_completed\":true}";}
 @ExceptionHandler(IllegalStateException.class) @ResponseStatus(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR)
 public String failure(){return "{\"controlled_error\":true}";}
}
