package system.monitoring.springlab;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.concurrent.*;
@RestController
public class AsyncTaskLab{
 private final JdbcTemplate jdbc;private final ExecutorService pool=Executors.newFixedThreadPool(2);
 private final java.util.concurrent.atomic.AtomicInteger completions=new java.util.concurrent.atomic.AtomicInteger();
 public AsyncTaskLab(JdbcTemplate jdbc){this.jdbc=jdbc;}
 @GetMapping("/spring-lab/task") public WebAsyncTask<String> task(@RequestParam("q")String q,@RequestParam("mode")String mode){
  var task=new WebAsyncTask<String>("timeout".equals(mode)?100L:5000L,()->{if("timeout".equals(mode)){long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);while(System.nanoTime()<until)try{Thread.sleep(100);}catch(InterruptedException cancelled){/* Complete late to exercise cleanup after the timeout callback. */}}return query(q,mode);});
  task.onTimeout(()->"timed_out");task.onError(()->"controlled_error");return task;
 }
 @GetMapping("/spring-lab/executor") public DeferredResult<String> executor(@RequestParam("q")String q,@RequestParam("mode")String mode,@RequestParam("api")String api){
  var result=new DeferredResult<String>(5000L);
  result.onCompletion(completions::incrementAndGet);
  Runnable work=()->{try{result.setResult(query(q,mode));}catch(RuntimeException error){result.setErrorResult("controlled_error");}};
  if("result".equals(api))pool.submit(work,"ignored");else if("submit".equals(api))pool.submit(work);else if("callable".equals(api))pool.submit(()->{work.run();return null;});else pool.execute(work);
  return result;
 }
 private String query(String q,String mode){
  if("raise".equals(mode))throw new IllegalStateException("controlled task error");
  if("parameterized".equals(mode))jdbc.queryForList("SELECT 1 WHERE ? = 'sample'",Integer.class,q);
  else if("constant".equals(mode))jdbc.queryForList("SELECT 1",Integer.class);
  else jdbc.queryForList("SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'",Integer.class);
  return "completed";
 }
 @jakarta.annotation.PreDestroy void stop(){pool.shutdownNow();}
 @GetMapping("/spring-lab/completions") public int completions(){return completions.get();}
}
