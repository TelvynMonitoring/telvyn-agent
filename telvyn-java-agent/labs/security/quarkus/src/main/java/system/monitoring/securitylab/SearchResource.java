package system.monitoring.securitylab;

import io.smallrye.common.annotation.Blocking;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

@Path("/security-lab")
@Blocking
public class SearchResource {
    @jakarta.inject.Inject OrmRepository repository;

    @GET @Path("/orm") @Produces("application/json")
    public java.util.List<OrmItem> orm(@jakarta.ws.rs.QueryParam("q") String q,@jakarta.ws.rs.QueryParam("mode") String mode) {
        return repository.search(q,mode);
    }

    public record Item(int id) {}

    @GET @Path("/items") @Produces("application/json")
    public java.util.List<Item> items(@jakarta.ws.rs.QueryParam("q") String q,@jakarta.ws.rs.QueryParam("mode") String mode)throws java.sql.SQLException {
        var result=new java.util.ArrayList<Item>();
        try(var connection=java.sql.DriverManager.getConnection("jdbc:h2:mem:iast")) {
            if("parameterized".equals(mode)) {
                try(var statement=connection.prepareStatement("SELECT 1 WHERE ? = 'sample'")){statement.setString(1,q);try(var rows=statement.executeQuery()){while(rows.next())result.add(new Item(rows.getInt(1)));}}
            }else {
                try(var statement=connection.createStatement();var rows=statement.executeQuery("SELECT 1 WHERE '"+q+"' = 'sample'")){while(rows.next())result.add(new Item(rows.getInt(1)));}
            }
        }
        return result;
    }

    @GET @Path("/search") @Produces("application/json")
    public String search(@jakarta.ws.rs.QueryParam("q") String q,@jakarta.ws.rs.QueryParam("mode") String mode)throws java.sql.SQLException {
        // Disposable in-memory JDBC database; no external database or request/SQL logging.
        try(var connection=java.sql.DriverManager.getConnection("jdbc:h2:mem:iast")) {
            if("parameterized".equals(mode)) {
                try(var statement=connection.prepareStatement("SELECT 1 WHERE ? = 'sample'")){statement.setString(1,q);try(var rows=statement.executeQuery()){while(rows.next())rows.getInt(1);}}
            }else if("constant".equals(mode)) {
                try(var statement=connection.createStatement();var rows=statement.executeQuery("SELECT 1")){rows.next();}
            }else if(q!=null) {
                String sql="SELECT 1 WHERE '"+q+"' = 'sample'";
                try(var statement=connection.createStatement();var rows=statement.executeQuery(sql)){while(rows.next())rows.getInt(1);}
            }
        }catch(java.sql.SQLException invalid){return "{\"request_completed\":true,\"database_rejected\":true}";}
        return "{\"request_completed\":true}";
    }

    @GET @Path("/outside") @Produces("application/json")
    public String outside(){return "{\"request_completed\":true}";}
}
