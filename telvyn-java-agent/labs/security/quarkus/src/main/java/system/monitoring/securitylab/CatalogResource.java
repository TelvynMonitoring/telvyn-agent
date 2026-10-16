package system.monitoring.securitylab;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import io.smallrye.common.annotation.NonBlocking;
import system.monitoring.security.InspectQuery;

/** Exercises a parameterized application route on the event loop, without a current span. */
@Path("/catalog")
public class CatalogResource {
    @GET @Path("/{id}") @Produces("application/json") @NonBlocking
    @InspectQuery({"q"})
    public String product(){return "{\"request_completed\":true}";}
}
