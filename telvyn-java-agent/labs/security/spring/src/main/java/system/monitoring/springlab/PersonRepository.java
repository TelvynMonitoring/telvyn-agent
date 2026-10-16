package system.monitoring.springlab;
import java.util.List;
public interface PersonRepository extends org.springframework.data.jpa.repository.JpaRepository<Person,Long> {
 List<Person> findByName(String name);
 @org.springframework.data.jpa.repository.Query("select p from Person p where p.name=:name")
 List<Person> named(@org.springframework.data.repository.query.Param("name")String name);
}
