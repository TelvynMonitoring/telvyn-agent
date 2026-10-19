# telvyn-java-api

API pública para a aplicação Java, sem dependências e sem efeito sozinha:
o agente Java do Telvyn (`telvyn-java-agent`) instrumenta estes métodos quando está anexado à JVM.

```java
import system.monitoring.telvyn.TelvynSecurity;

TelvynSecurity.trackUserLoginFailure(login, false);        // conta inexistente
TelvynSecurity.trackUserLoginSuccess(login, user.getId()); // usuário bloqueado: já respondeu com o bloqueio e lança exceção
TelvynSecurity.trackUserSignup(login, user.getId());
TelvynSecurity.setUser(user.getId());                       // usuário logado da requisição
TelvynSecurity.isUserBlocked(user.getId());
```

Use para logins e cadastros que o agente não reconhece sozinho (fora do Spring Security). Nunca passe a senha.
A exceção de bloqueio encerra a requisição, cuja resposta já foi enviada: não a capture.

Java 8+. Ainda não publicada em repositório Maven: instale com `mvn install` a partir desta pasta.
