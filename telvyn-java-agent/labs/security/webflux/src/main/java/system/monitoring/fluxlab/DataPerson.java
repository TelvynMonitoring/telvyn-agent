package system.monitoring.fluxlab;
@org.springframework.data.relational.core.mapping.Table("data_person")
public record DataPerson(@org.springframework.data.annotation.Id Long id,String name){}
