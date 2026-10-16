package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * IAST request scope for plain servlets (javax and jakarta), the way servlet applications receive requests.
 * Only routes listed in telvyn.security.query-routes open a scope; Spring MVC keeps its own path (SpringMvcSecurity).
 */
public final class ServletIast {
    private static final Object CLOSED=new Object();
    private ServletIast() {}
    public static void install(Instrumentation instrumentation){
        if(!Boolean.getBoolean("telvyn.iast.enabled"))return;
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(namedOneOf("javax.servlet.http.HttpServlet","jakarta.servlet.http.HttpServlet"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Scope.class).on(named("service").and(takesArguments(2))
                .and(takesArgument(0,namedOneOf("javax.servlet.http.HttpServletRequest","jakarta.servlet.http.HttpServletRequest"))))))
            .installOn(instrumentation);
    }
    // Through the public interface: forwarded and included requests are container classes that are not public.
    private static final ClassValue<Class<?>> API=new ClassValue<>(){@Override protected Class<?> computeValue(Class<?> type){
        for(Class<?> current=type;current!=null;current=current.getSuperclass())for(Class<?> api:current.getInterfaces())
            if(api.getName().equals("javax.servlet.http.HttpServletRequest")||api.getName().equals("jakarta.servlet.http.HttpServletRequest"))return api;
        return type;
    }};
    public static Object open(Object servlet,Object request){
        try{
            // A forwarded or included request keeps the scope of the request that received the input.
            if(servlet.getClass().getName().startsWith("org.springframework.")||IastRuntime.capture()!=null)return CLOSED;
            SpringMvcSecurity.start();
            var type=API.get(request.getClass());
            String verb=(String)type.getMethod("getMethod").invoke(request);
            String path=(String)type.getMethod("getServletPath").invoke(request);
            Object extra=type.getMethod("getPathInfo").invoke(request);
            if(extra instanceof String info)path+=info;
            if(!SpringMvcSecurity.servletSelected(verb,path))return CLOSED;
            // The servlet mapping, not the concrete path: what follows the mapping is input.
            String servletPath=(String)type.getMethod("getServletPath").invoke(request);
            return new Object[]{IastRuntime.openRequest(verb,servletPath+(extra==null?"":"/*"))};
        }catch(ReflectiveOperationException|RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("servlet integration unavailable");return CLOSED;}
    }
    public static void close(Object token){if(token instanceof Object[] opened)IastRuntime.exit(opened[0]);}
    public static class Scope {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static Object enter(@Advice.This Object servlet,@Advice.Argument(0)Object request){return open(servlet,request);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Object token){close(token);}
    }
}
