package jakarta.ws.rs;

import java.lang.annotation.*;

/** Só para os testes: o agent reconhece a anotação pelo nome, e o agent não depende da API JAX-RS. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface QueryParam {
    String value();
}
