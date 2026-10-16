package system.monitoring.securitylab;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;

@ApplicationScoped
public class OrmRepository implements PanacheRepository<OrmItem> {
    public List<OrmItem> search(String q,String mode) {
        String value=q.trim().toLowerCase();
        return switch(mode) {
            case "list-unsafe" -> list("name = '"+value+"'");
            case "find-unsafe" -> find("name = '"+value+"'").list();
            case "count-unsafe" -> count("name = '"+value+"'")>0?list("name = ?1","sample"):List.of();
            case "count-safe" -> count("name = ?1",value)>0?list("name = ?1","sample"):List.of();
            case "jpa-unsafe" -> getEntityManager().createQuery("from OrmItem where name = '"+value+"'",OrmItem.class).getResultList();
            case "native-unsafe" -> getEntityManager().createNativeQuery("select * from OrmItem where name = '"+value+"'",OrmItem.class).getResultList();
            case "find-safe" -> find("name = ?1",value).list();
            case "jpa-safe" -> getEntityManager().createQuery("from OrmItem where name = :name",OrmItem.class).setParameter("name",value).getResultList();
            case "native-safe" -> getEntityManager().createNativeQuery("select * from OrmItem where name = ?1",OrmItem.class).setParameter(1,value).getResultList();
            default -> list("name = ?1",value);
        };
    }
}
