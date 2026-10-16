package system.monitoring.springlab;
import java.util.List;
@org.springframework.stereotype.Repository
public class PersonQueries {
 @jakarta.persistence.PersistenceContext jakarta.persistence.EntityManager em;
 public List<Person> search(String q,String mode){
  if("parameterized".equals(mode))return em.createQuery("select p from Person p where p.name=:q",Person.class).setParameter("q",q).getResultList();
  if("native".equals(mode))return em.createNativeQuery("SELECT * FROM person WHERE name='"+q.trim().toLowerCase()+"'",Person.class).getResultList();
  return em.createQuery("select p from Person p where p.name='"+q.trim().toLowerCase()+"'",Person.class).getResultList();
 }
}
