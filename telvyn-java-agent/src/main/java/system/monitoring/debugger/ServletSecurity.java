package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Detecção e bloqueio de ataques em qualquer servlet (javax ou jakarta): Tomcat, Jetty, Undertow, WebLogic,
 * WebSphere, JBoss/WildFly e Jersey ou RESTEasy sobre servlet pela instrumentação de Servlet.
 * Início da requisição (cabeçalhos, cookies, query, endereço, IP, usuário do principal) e status no fim; o corpo
 * não é lido aqui para não consumir o que a aplicação vai ler. No Spring, as fases do Spring reaproveitam o estado.
 * A requisição começa na cadeia de filtros: requisições respondidas só por filtros (login do Spring Security,
 * por exemplo) também passam pela inspeção, e o bloqueio decidido num filtro termina ali.
 */
public final class ServletSecurity {
    private ServletSecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(hasSuperType(namedOneOf("javax.servlet.http.HttpServlet", "jakarta.servlet.http.HttpServlet")).and(not(isInterface())),
                LoaderMatchers.canSee("javax.servlet.http.HttpServlet", "jakarta.servlet.http.HttpServlet"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Service.class).on(named("service").and(not(isAbstract())).and(takesArguments(2))
                .and(takesArgument(0, namedOneOf("javax.servlet.http.HttpServletRequest", "jakarta.servlet.http.HttpServletRequest"))))))
            .installOn(instrumentation);
        Agents.builder()
            .type(hasSuperType(namedOneOf("javax.servlet.FilterChain", "jakarta.servlet.FilterChain")).and(not(isInterface())),
                LoaderMatchers.canSee("javax.servlet.FilterChain", "jakarta.servlet.FilterChain"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Chain.class).on(named("doFilter").and(not(isAbstract())).and(takesArguments(2)))))
            .installOn(instrumentation);
    }

    public static class Service {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Argument(0) Object request, @Advice.Argument(1) Object response) { return SpringMvcSecurity.requestStart(request, response); }
        // Bloqueio durante a leitura do corpo: a resposta já foi enviada, a requisição só termina.
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Argument(0) Object request, @Advice.Argument(1) Object response, @Advice.Thrown(readOnly = false) Throwable thrown) {
            SpringMvcSecurity.requestEnd(request, response);
            if (SpringMvcSecurity.isBlock(thrown)) thrown = null;
        }
    }

    public static class Chain {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Argument(0) Object request, @Advice.Argument(1) Object response) { return SpringMvcSecurity.requestStart(request, response); }
        // Bloqueio no meio de um filtro (login de usuário bloqueado): a resposta já foi escrita, a cadeia só termina.
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Argument(0) Object request, @Advice.Argument(1) Object response, @Advice.Thrown(readOnly = false) Throwable thrown) {
            SpringMvcSecurity.requestEnd(request, response);
            if (SpringMvcSecurity.isBlock(thrown)) thrown = null;
        }
    }
}
