package system.monitoring.securitylab;

import jakarta.ws.rs.*;
import system.monitoring.security.QueryRouteScope;
import system.monitoring.security.InspectQuery;

/** Focused scope diagnostic; no server or requests are started. */
@Path("/catalog")
public class QueryScopeCheck {
    @GET @Path("/{id}") public String read(){return "";}
    @POST @Path("/{id}") public String write(){return "";}
    @GET @Path("/other") public String other(){return "";}
    @GET @InspectQuery({"legacy"}) public String legacy(){return "";}
    public static void main(String[] args)throws Exception {
        var read=QueryScopeCheck.class.getMethod("read");
        var scope=new QueryRouteScope("GET /catalog/{id}");
        assert scope.parameters(read,"GET").equals(java.util.Set.of("q"));
        assert scope.parameters(read,"HEAD").isEmpty();
        assert scope.parameters(QueryScopeCheck.class.getMethod("write"),"POST").isEmpty();
        assert scope.parameters(QueryScopeCheck.class.getMethod("other"),"GET").isEmpty();
        assert new QueryRouteScope("").parameters(read,"GET").isEmpty();
        assert new QueryRouteScope("GET /catalog/123").parameters(read,"GET").isEmpty();
        assert scope.parameters(QueryScopeCheck.class.getMethod("legacy"),"GET").equals(java.util.Set.of("legacy"));
        try{new QueryRouteScope("GET /*");throw new AssertionError("wildcard accepted");}catch(IllegalArgumentException expected){}
        System.out.println("Query scope: template, verb, exclusion, default-off, literal path, annotation compatibility and wildcard rejection passed");
    }
}
