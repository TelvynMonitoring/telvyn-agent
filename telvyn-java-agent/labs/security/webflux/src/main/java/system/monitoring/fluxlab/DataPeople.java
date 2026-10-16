package system.monitoring.fluxlab;
import reactor.core.publisher.Flux;
public interface DataPeople extends org.springframework.data.repository.reactive.ReactiveCrudRepository<DataPerson,Long>{
 Flux<DataPerson> findByName(String name);
 @org.springframework.data.r2dbc.repository.Query("SELECT id,name FROM data_person WHERE name=:name")
 Flux<DataPerson> named(String name);
}
