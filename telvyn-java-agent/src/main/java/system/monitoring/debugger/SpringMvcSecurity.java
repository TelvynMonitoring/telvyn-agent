package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.*;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/** Spring MVC hooks; no Spring dependency and no request body/header inspection. */
public final class SpringMvcSecurity {
    private static final ThreadLocal<Method> selected=new ThreadLocal<>();
    private static final ThreadLocal<String[]> selectedRoute=new ThreadLocal<>();
    private static boolean started;
    private static Set<String> routes=Set.of();
    private static LocalAttackReporter attacks,iast;
    private static LocalAttackDetection detector;
    private static ThreadPoolExecutor worker;
    private SpringMvcSecurity() {}
    public static Object selection(){return selected.get();}
    public static void selection(Object method){if(method instanceof Method value)selected.set(value);else selected.remove();}
    private static String setting(String name,String fallback){String value=System.getProperty("telvyn.security."+name);if(value==null)value=System.getenv("TELVYN_SECURITY_"+name.toUpperCase(Locale.ROOT).replace('.','_').replace('-','_'));return value==null?fallback:value;}
    public static void install(Instrumentation instrumentation){
        if(!Boolean.parseBoolean(setting("spring.enabled","false")))return;
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(named("org.springframework.web.servlet.mvc.method.AbstractHandlerMethodAdapter"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Dispatch.class).on(named("handle").and(takesArguments(3)))))
            .installOn(instrumentation);
        if(Boolean.getBoolean("telvyn.iast.enabled"))new AgentBuilder.Default().disableClassFormatChanges()
            .type(named("org.springframework.jdbc.core.JdbcTemplate"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Jdbc.class).on(isPublic().and(namedOneOf("execute","query","queryForList","queryForObject","update","batchUpdate")).and(takesArgument(0,String.class)))))
            .installOn(instrumentation);
        new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerAdapter"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(ReactiveDispatch.class).on(named("handle").and(takesArguments(2)))))
            .installOn(instrumentation);
        FunctionalWebFluxSecurity.install(instrumentation);
        if(Boolean.getBoolean("telvyn.iast.enabled"))new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.web.context.request.async.WebAsyncTask"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(WebTaskInterceptor.class).on(named("getInterceptor").and(takesArguments(0))))).installOn(instrumentation);
        if(Boolean.getBoolean("telvyn.iast.enabled"))new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.web.context.request.async.DeferredResult"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(DeferredCompletion.class).on(named("onCompletion"))).visit(Advice.to(DeferredTimeout.class).on(named("onTimeout"))).visit(Advice.to(DeferredError.class).on(named("onError")))).installOn(instrumentation);
        if(Boolean.getBoolean("telvyn.iast.enabled"))new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.aop.interceptor.AsyncExecutionAspectSupport"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(AsyncTask.class).on(named("doSubmit").and(takesArguments(3)))))
            .installOn(instrumentation);
    }
    static synchronized void start(){
        if(started)return;started=true;
        var configured=new HashSet<String>();
        for(String entry:setting("query-routes","").split(",",-1)){
            String route=entry.trim();if(route.isEmpty())continue;
            if(!route.matches("(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /[A-Za-z0-9_./{}*-]*")||route.length()>512||configured.size()>=64)throw new IllegalArgumentException("invalid Spring query route scope");
            configured.add(route);
        }
        routes=Set.copyOf(configured);
        boolean enabled=Boolean.parseBoolean(setting("enabled","false"));
        if(enabled){
            attacks=reporter("events");detector=new LocalAttackDetection();
            worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(64),r->{var t=new Thread(r,"telvyn-spring-security");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
        }
        SecuritySensorState.attack(enabled);
        if(Boolean.getBoolean("telvyn.iast.enabled")){
            iast=reporter("iast");IastRuntime.configureSources(method->method.equals(selected.get()));
            IastRuntime.configureTrace(SpringMvcSecurity::trace);
            IastRuntime.configureRequest(selectedRoute::get);
            IastRuntime.configure(finding->{var ids=IastRuntime.traceIds();if(ids==null)ids=trace();iast.reportIast(finding,ids[0],ids[1]);});
        }
        Runtime.getRuntime().addShutdownHook(new Thread(()->{if(worker!=null)worker.shutdownNow();if(attacks!=null)attacks.close();if(iast!=null)iast.close();if(detector!=null)detector.close();},"telvyn-spring-security-stop"));
    }
    private static LocalAttackReporter reporter(String channel){
        return new LocalAttackReporter(Collector.url()+"/v1/security/"+channel,SnapshotSink.service(),SnapshotSink.host(),ProbeMetricSink.environment(),ProbeMetricSink.version(),"query-allowlist-1");
    }
    // Servlet routes are the request path: exact, or every path under a prefix written as "/prefix/**".
    static boolean servletSelected(String verb,String path){
        if(routes.contains(verb+" "+path))return true;
        for(String route:routes)if(route.endsWith("/**")&&route.startsWith(verb+" ")&&(path+"/").startsWith(route.substring(verb.length()+1,route.length()-2)))return true;
        return false;
    }
    public static Method open(Object request,Object handler){
        Method previous=selected.get();selected.remove();selectedRoute.remove();
        try{
            start();
            if(worker==null&&!Boolean.getBoolean("telvyn.iast.enabled"))return previous;
            var requestType=request.getClass();
            String verb=(String)requestType.getMethod("getMethod").invoke(request);
            Object pattern=requestType.getMethod("getAttribute",String.class).invoke(request,"org.springframework.web.servlet.HandlerMapping.bestMatchingPattern");
            if(!(pattern instanceof String route)||!routes.contains(verb+" "+route))return previous;
            Method method=(Method)handler.getClass().getMethod("getMethod").invoke(handler);
            String query=(String)requestType.getMethod("getQueryString").invoke(request);
            var ids=trace();long began=System.nanoTime();
            try{
                var values=LocalAttackDetection.permittedQuery(query,Set.of("q"));
                if(worker!=null&&!values.isEmpty())worker.execute(()->{try{attacks.report(detector.inspectPermittedQuery(values),ids[0],ids[1]);}catch(RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("Spring analysis failure");}});
            }catch(LocalAttackDetection.InputLimitException limit){if(attacks!=null)attacks.report(new LocalAttackDetection.Result("limit",List.of(),null,(System.nanoTime()-began)/1000),ids[0],ids[1]);return previous;}
            catch(IllegalArgumentException invalid){if(attacks!=null)attacks.report(new LocalAttackDetection.Result("error",List.of(),null,(System.nanoTime()-began)/1000),ids[0],ids[1]);return previous;}
            catch(RejectedExecutionException full){LocalAttackReporter.reportLoss("Spring analysis queue full");}
            selected.set(method);selectedRoute.set(new String[]{verb,route});
        }catch(ReflectiveOperationException|RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("Spring integration unavailable");}
        return previous;
    }
    public static void close(Method previous){if(previous==null)selected.remove();else selected.set(previous);}
    public record ReactiveScope(Method previous,Method method,boolean allowed) {}
    public static ReactiveScope reactive(Object exchange,Object handler){
        Method previous=selected.get();selected.remove();
        try{
            start();if(worker==null&&!Boolean.getBoolean("telvyn.iast.enabled"))return new ReactiveScope(previous,null,false);
            var loader=Thread.currentThread().getContextClassLoader();if(Boolean.getBoolean("telvyn.iast.enabled"))ReactorIast.install(loader);
            var exchangeApi=Class.forName("org.springframework.web.server.ServerWebExchange",false,loader);
            Object request=exchangeApi.getMethod("getRequest").invoke(exchange);
            var requestApi=Class.forName("org.springframework.http.server.reactive.ServerHttpRequest",false,loader);
            String verb=requestApi.getMethod("getMethod").invoke(request).toString();
            String key=(String)Class.forName(handler==null?"org.springframework.web.reactive.function.server.RouterFunctions":"org.springframework.web.reactive.HandlerMapping",false,loader).getField(handler==null?"MATCHING_PATTERN_ATTRIBUTE":"BEST_MATCHING_PATTERN_ATTRIBUTE").get(null);
            Object pattern=exchangeApi.getMethod("getAttribute",String.class).invoke(exchange,key);
            if(pattern==null)return new ReactiveScope(previous,null,false);
            String route=pattern instanceof String value?value:(String)Class.forName("org.springframework.web.util.pattern.PathPattern",false,loader).getMethod("getPatternString").invoke(pattern);
            if(!routes.contains(verb+" "+route))return new ReactiveScope(previous,null,false);
            Method method=handler==null?null:(Method)Class.forName("org.springframework.web.method.HandlerMethod",false,loader).getMethod("getMethod").invoke(handler);
            String query=((java.net.URI)requestApi.getMethod("getURI").invoke(request)).getRawQuery();
            var ids=trace();long began=System.nanoTime();
            try{
                var values=LocalAttackDetection.permittedQuery(query,Set.of("q"));
                if(worker!=null&&!values.isEmpty())worker.execute(()->{try{attacks.report(detector.inspectPermittedQuery(values),ids[0],ids[1]);}catch(RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("reactive analysis failure");}});
            }catch(LocalAttackDetection.InputLimitException limit){if(attacks!=null)attacks.report(new LocalAttackDetection.Result("limit",List.of(),null,(System.nanoTime()-began)/1000),ids[0],ids[1]);return new ReactiveScope(previous,null,false);}
            catch(IllegalArgumentException invalid){if(attacks!=null)attacks.report(new LocalAttackDetection.Result("error",List.of(),null,(System.nanoTime()-began)/1000),ids[0],ids[1]);return new ReactiveScope(previous,null,false);}
            catch(RejectedExecutionException full){LocalAttackReporter.reportLoss("reactive analysis queue full");}
            if(method!=null){selected.set(method);selectedRoute.set(new String[]{verb,route});}return new ReactiveScope(previous,method,true);
        }catch(ReflectiveOperationException|RuntimeException|LinkageError failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("reactive integration unavailable");return new ReactiveScope(previous,null,false);}
    }
    private static String[] trace(){
        try{
            var loader=Thread.currentThread().getContextClassLoader();var span=Class.forName("io.opentelemetry.api.trace.Span",false,loader);
            var context=Class.forName("io.opentelemetry.api.trace.SpanContext",false,loader);
            Object current=span.getMethod("getSpanContext").invoke(span.getMethod("current").invoke(null));
            if(Boolean.TRUE.equals(context.getMethod("isValid").invoke(current)))return new String[]{(String)context.getMethod("getTraceId").invoke(current),(String)context.getMethod("getSpanId").invoke(current)};
        }catch(ReflectiveOperationException|LinkageError unavailable){ /* No valid application trace context. */ }
        return new String[]{null,null};
    }
    public static void jdbc(String sql,String sink){
        String prefix=System.getProperty("telvyn.iast.application-package","");
        StackWalker.getInstance().walk(frames->frames.filter(frame->!prefix.isEmpty()&&frame.getClassName().startsWith(prefix)&&!frame.getClassName().startsWith("system.monitoring.debugger.")).findFirst()).ifPresent(frame->IastRuntime.jdbc(sql,frame.getClassName()+"#"+frame.getMethodName(),frame.getLineNumber(),sink));
    }
    public static class Dispatch {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static Method enter(@Advice.Argument(0)Object request,@Advice.Argument(2)Object handler){return open(request,handler);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Method previous){close(previous);}
    }
    public static class Jdbc {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(0)String sql,@Advice.Origin("#t.#m")String origin){jdbc(sql,origin);}
    }
    public static class ReactiveDispatch {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static ReactiveScope enter(@Advice.Argument(0)Object exchange,@Advice.Argument(1)Object handler){return reactive(exchange,handler);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter ReactiveScope scope,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result){if(scope!=null){if(scope.method()!=null&&result!=null)result=ReactorIast.dispatch(result,scope.method());close(scope.previous());}}
    }
    public static class AsyncTask {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(value=0,readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object task){task=IastAsync.callable(task,IastRuntime.capture());}
    }
    public static class WebTaskInterceptor {
        @Advice.OnMethodExit(suppress=Throwable.class) public static void exit(@Advice.This Object task,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result){result=IastAsync.webAsyncInterceptor(task,result);}
    }
    public static class DeferredCompletion {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(value=0,readOnly=false)Runnable callback,@Advice.FieldValue("completionCallback")Runnable previous){callback=IastAsync.completion(callback,previous);}
    }
    public static class DeferredTimeout {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(value=0,readOnly=false)Runnable callback,@Advice.FieldValue("timeoutCallback")Runnable previous){callback=IastAsync.completion(callback,previous);}
    }
    public static class DeferredError {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(value=0,readOnly=false)java.util.function.Consumer<Throwable> callback,@Advice.FieldValue("errorCallback")java.util.function.Consumer<Throwable> previous){callback=IastAsync.completionError(callback,previous);}
    }
}
