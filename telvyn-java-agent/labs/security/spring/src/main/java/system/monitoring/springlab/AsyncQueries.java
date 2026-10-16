package system.monitoring.springlab;
import java.util.List;
import java.util.concurrent.CompletableFuture;
@org.springframework.stereotype.Service
public class AsyncQueries {
 private final org.springframework.jdbc.core.JdbcTemplate jdbc;
 public AsyncQueries(org.springframework.jdbc.core.JdbcTemplate jdbc){this.jdbc=jdbc;}
 @org.springframework.scheduling.annotation.Async public CompletableFuture<List<Integer>> load(String q,String mode){
  if("raise".equals(mode))throw new IllegalStateException("controlled async error");
  List<Integer> values="parameterized".equals(mode)?jdbc.queryForList("SELECT 1 WHERE ? = 'sample'",Integer.class,q):jdbc.queryForList("SELECT 1 WHERE '"+q.trim().toLowerCase()+"' = 'sample'",Integer.class);
  return CompletableFuture.completedFuture(values);
 }
}
