package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.*;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/** Spring MVC hooks (no Spring dependency): attack detection and blocking over the whole request, IAST sources. */
public final class SpringMvcSecurity {
    private static final ThreadLocal<Method> selected=new ThreadLocal<>();
    private static final ThreadLocal<String[]> selectedRoute=new ThreadLocal<>();
    // Método selecionado antes de cada handle (pilha: forward/include aninham handle) e se a requisição foi bloqueada.
    private static final ThreadLocal<Deque<Optional<Method>>> previousSelection=ThreadLocal.withInitial(ArrayDeque::new);
    private static final ThreadLocal<Boolean> blockedRequest=new ThreadLocal<>();
    private static boolean started;
    private static Set<String> routes=Set.of();
    private static volatile LocalAttackReporter attacks;
    private static LocalAttackReporter iast;
    private static volatile LocalAttackDetection detector;
    private static volatile ThreadPoolExecutor worker;
    /** Eventos das regras completas (conjunto recomendado do Datadog). */
    private static volatile LocalAttackReporter waf;
    private static final String STATE="telvyn.security.waf";
    /** Requisição em curso nesta thread (requisição, resposta, estado), para os eventos de login do Spring Security. */
    private static final ThreadLocal<Object[]> current=new ThreadLocal<>();
    static Object[] current(){return current.get();}
    /** Requisição em curso definida por outro framework (Vert.x) enquanto o handler roda; null limpa. */
    static void current(Object[] value){if(value==null)current.remove();else current.set(value);}
    /** Bloqueio decidido no corpo: interrompe o handler; a resposta de bloqueio já foi escrita. */
    public static final class BlockedRequestException extends RuntimeException {
        public BlockedRequestException(){super("request blocked by Telvyn",null,false,false);}
    }
    /** Exceção de bloqueio, inclusive embrulhada por outra (frameworks costumam embrulhar falhas de acesso a dados). */
    public static boolean isBlock(Throwable thrown){for(int i=0;thrown!=null&&i<10;i++,thrown=thrown.getCause())if(thrown instanceof BlockedRequestException)return true;return false;}
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
        // Início e fim de toda requisição Spring MVC: IP, usuário, cabeçalhos, cookies, query, endereço; status da resposta.
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(named("org.springframework.web.servlet.DispatcherServlet"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(RequestPhase.class).on(named("doDispatch").and(takesArguments(2)))))
            .installOn(instrumentation);
        // Corpo (@RequestBody) depois de convertido, antes do controller.
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(named("org.springframework.web.servlet.mvc.method.annotation.AbstractMessageConverterMethodArgumentResolver"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(BodyPhase.class).on(named("readWithMessageConverters").and(takesArguments(3)))))
            .installOn(instrumentation);
        if(Boolean.getBoolean("telvyn.iast.enabled"))new AgentBuilder.Default().disableClassFormatChanges()
            .type(named("org.springframework.jdbc.core.JdbcTemplate"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Jdbc.class).on(isPublic().and(namedOneOf("execute","query","queryForList","queryForObject","update","batchUpdate")).and(takesArgument(0,String.class)))))
            .installOn(instrumentation);
        new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerAdapter"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(ReactiveDispatch.class).on(named("handle").and(takesArguments(2)))))
            .installOn(instrumentation);
        FunctionalWebFluxSecurity.install(instrumentation);
        new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.web.reactive.function.server.support.HandlerFunctionAdapter"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(FunctionalDispatch.class).on(named("handle").and(takesArguments(2)))))
            .installOn(instrumentation);
        new AgentBuilder.Default().disableClassFormatChanges().type(named("org.springframework.web.reactive.result.method.annotation.AbstractMessageReaderArgumentResolver"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(ReactiveBody.class).on(named("readBody").and(takesArguments(5)))))
            .installOn(instrumentation);
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
        // Runs on the first request; a failure keeps the application running and reports its reason once, like the Node SDK.
        try{startSensors();}
        catch(RuntimeException|LinkageError failure){
            SecuritySensorState.attackFailed();if(Boolean.getBoolean("telvyn.iast.enabled"))SecuritySensorState.iastFailed();
            System.err.println("[telvyn] Spring security sensor could not start; application startup continues."+TelvynDebuggerAgent.reason(failure));
            throw failure;
        }
    }
    private static void startSensors(){
        var configured=new HashSet<String>();
        for(String entry:setting("query-routes","").split(",",-1)){
            String route=entry.trim();if(route.isEmpty())continue;
            if(!route.matches("(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /[A-Za-z0-9_./{}*-]*")||route.length()>512||configured.size()>=64)throw new IllegalArgumentException("invalid Spring query route scope");
            configured.add(route);
        }
        routes=Set.copyOf(configured);
        boolean enabled=Boolean.parseBoolean(setting("enabled","false"));
        if(enabled)startAttack();
        SecuritySensorState.attack(enabled);
        if(Boolean.getBoolean("telvyn.iast.enabled")){
            iast=reporter("iast");IastRuntime.configureSources(method->method.equals(selected.get()));
            IastRuntime.configureTrace(SpringMvcSecurity::trace);
            IastRuntime.configureRequest(selectedRoute::get);
            IastRuntime.configure(finding->{if(Boolean.FALSE.equals(RemoteConfig.security("iast")))return;var ids=IastRuntime.traceIds();if(ids==null)ids=trace();iast.reportIast(finding,ids[0],ids[1]);});
        }
        Runtime.getRuntime().addShutdownHook(new Thread(()->{if(worker!=null)worker.shutdownNow();if(attacks!=null)attacks.close();if(iast!=null)iast.close();if(detector!=null)detector.close();},"telvyn-spring-security-stop"));
    }
    private static synchronized void startAttack(){
        if(worker!=null)return;
        attacks=reporter("events");detector=new LocalAttackDetection();
        waf=new LocalAttackReporter(Collector.url()+"/v1/security/events",SnapshotSink.service(),SnapshotSink.host(),ProbeMetricSink.environment(),ProbeMetricSink.version(),WafInspector.RULES_VERSION);
        try{WafInspector.engine();}catch(Exception|LinkageError failure){System.err.println("[telvyn] WAF rules could not load; attack detection stays on the legacy query rules."+TelvynDebuggerAgent.reason(failure));waf=null;}
        worker=new ThreadPoolExecutor(1,1,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(64),r->{var t=new Thread(r,"telvyn-spring-security");t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
    }
    /** Configuração remota: liga ou desliga a detecção de ataques com a aplicação rodando. */
    static synchronized void remoteAttack(boolean enabled){
        if("error".equals(SecuritySensorState.attack()))return;
        if(enabled)startAttack();
        else if(worker!=null){
            var stoppedWorker=worker;var stoppedAttacks=attacks;var stoppedDetector=detector;var stoppedWaf=waf;
            worker=null;attacks=null;detector=null;waf=null;
            if(stoppedWaf!=null)stoppedWaf.close();
            stoppedWorker.shutdownNow();if(stoppedAttacks!=null)stoppedAttacks.close();if(stoppedDetector!=null)stoppedDetector.close();
        }
        SecuritySensorState.attack(enabled);
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
    private static Object attribute(Object request,String name){try{return request.getClass().getMethod("getAttribute",String.class).invoke(request,name);}catch(ReflectiveOperationException|RuntimeException unavailable){return null;}}
    private static void attribute(Object request,String name,Object value){try{request.getClass().getMethod("setAttribute",String.class,Object.class).invoke(request,name,value);}catch(ReflectiveOperationException|RuntimeException unavailable){ /* sem estado: só o início é inspecionado */ }}
    /** Usuário logado como o Datadog no Java: Spring Security (exceto anônimo); senão o principal do servlet. */
    static String loggedUser(Object request){
        try{
            var holder=Class.forName("org.springframework.security.core.context.SecurityContextHolder",false,Thread.currentThread().getContextClassLoader());
            Object context=holder.getMethod("getContext").invoke(null);
            Object auth=context==null?null:context.getClass().getMethod("getAuthentication").invoke(context);
            if(auth!=null&&!auth.getClass().getName().endsWith("AnonymousAuthenticationToken")&&Boolean.TRUE.equals(auth.getClass().getMethod("isAuthenticated").invoke(auth))){
                Object name=auth.getClass().getMethod("getName").invoke(auth);
                if(name instanceof String value&&!value.isBlank())return value;
            }
        }catch(ReflectiveOperationException|RuntimeException|LinkageError unavailable){ /* sem Spring Security */ }
        try{
            Object principal=request.getClass().getMethod("getUserPrincipal").invoke(request);
            Object name=principal==null?null:principal.getClass().getMethod("getName").invoke(principal);
            return name instanceof String value&&!value.isBlank()?value:null;
        }catch(ReflectiveOperationException|RuntimeException unavailable){return null;}
    }
    /** Reporta as regras novas da fase e decide o bloqueio por regra. */
    static LocalAttackReporter wafReporter(){start();return waf;}
    static boolean decide(WafInspector.State state,WafInspector.Evaluation evaluation,LocalAttackReporter reporter){return decide(state,evaluation,reporter,true);}
    /** blockable=false: só detecta (pontos onde o Datadog também não bloqueia, como o graphql-java e o gRPC). */
    static boolean decide(WafInspector.State state,WafInspector.Evaluation evaluation,LocalAttackReporter reporter,boolean blockable){
        if(!"match".equals(evaluation.outcome())){
            if(("timeout".equals(evaluation.outcome())&&!state.timeoutReported)||"error".equals(evaluation.outcome())){
                state.timeoutReported|="timeout".equals(evaluation.outcome());
                reporter.reportWaf(evaluation.outcome(),null,null,evaluation.elapsedUs(),WafInspector.engineVersion(),state.ip,state.method,state.path,state.userAgent,state.user,null,state.trace[0],state.trace[1]);
            }
            return false;
        }
        boolean block=blockable&&!state.blocked&&JavaProtection.allowBlocking()&&!JavaProtection.passed(state.ip)&&evaluation.matches().stream().anyMatch(m->"blocking".equals(JavaProtection.ruleMode(m.rule())));
        for(var match:evaluation.matches())reporter.reportWaf("match",match.rule(),match.address(),evaluation.elapsedUs(),WafInspector.engineVersion(),state.ip,state.method,state.path,state.userAgent,state.user,block&&"blocking".equals(JavaProtection.ruleMode(match.rule()))?"rule":null,state.trace[0],state.trace[1]);
        return block;
    }
    private static boolean block(WafInspector.State state,Object request,Object response,String by,LocalAttackReporter reporter){
        if(JavaProtection.respond(request,response)==null)return false;
        state.blocked=true;
        if(!"rule".equals(by))reporter.reportWaf("blocked",null,null,0,WafInspector.engineVersion(),state.ip,state.method,state.path,state.userAgent,state.user,by,state.trace[0],state.trace[1]);
        return true;
    }
    /** Início da requisição (DispatcherServlet): devolve true quando bloqueou e respondeu. */
    public static boolean requestStart(Object request,Object response){
        start();
        var reporter=waf;
        if(reporter==null)return false;
        if(attribute(request,STATE) instanceof WafInspector.State open){
            if(open.closed)return false;
            open.depth++;
            // A inspeção começa na cadeia de filtros, antes da autenticação: o usuário logado chega depois.
            return open.user==null&&!open.blocked&&userPhase(open,request,response,loggedUser(request),reporter);
        }
        try{
            String ip=JavaProtection.clientIp(request);
            Object agent=request.getClass().getMethod("getHeader",String.class).invoke(request,"User-Agent");
            var state=WafInspector.open(ip,requestMethod(request),requestPath(request),agent instanceof String value?value:null,trace());
            attribute(request,STATE,state);
            current.set(new Object[]{request,response,state});
            state.user=loggedUser(request);
            if(JavaProtection.allowBlocking()&&JavaProtection.denied(ip))return block(state,request,response,"ip",reporter);
            if(state.user!=null&&JavaProtection.allowBlocking()&&JavaProtection.userBlocked(state.user)&&!JavaProtection.passed(ip))return block(state,request,response,"user",reporter);
            var data=WafInspector.requestStart(request);
            if(ip!=null)data.put("http.client_ip",ip);
            if(state.user!=null)data.put("usr.id",state.user);
            return decide(state,WafInspector.run(state,data),reporter)&&block(state,request,response,"rule",reporter);
        }catch(Exception|LinkageError failure){LocalAttackReporter.reportLoss("request inspection failure");return false;}
    }
    /** Usuário identificado (logado ou no login): bloqueio pela lista de usuários e regras sobre usr.id. */
    static boolean userPhase(WafInspector.State state,Object request,Object response,String user,LocalAttackReporter reporter){
        if(user==null)return false;
        state.user=user;
        if(JavaProtection.allowBlocking()&&JavaProtection.userBlocked(user)&&!JavaProtection.passed(state.ip))return block(state,request,response,"user",reporter);
        return decide(state,WafInspector.run(state,Map.of("usr.id",user)),reporter)&&block(state,request,response,"rule",reporter);
    }
    /** Fim da requisição: status da resposta e liberação do contexto. */
    public static void requestEnd(Object request,Object response){
        if(!(attribute(request,STATE) instanceof WafInspector.State state)||state.closed||--state.depth>0)return;
        try{
            current.remove();
            var reporter=waf;
            Object status=response.getClass().getMethod("getStatus").invoke(response);
            if(reporter!=null&&!state.blocked)decide(state,WafInspector.run(state,Map.of("server.response.status",String.valueOf(status))),reporter);
        }catch(ReflectiveOperationException|RuntimeException|LinkageError ignored){ /* status indisponível */ }
        finally{WafInspector.close(state);}
    }
    /** Fase de rota (handler): parâmetros de rota e formulário. */
    static boolean routePhase(Object request,Object response){
        var reporter=waf;
        if(reporter==null||!(attribute(request,STATE) instanceof WafInspector.State state)||state.blocked||state.routeInspected)return false;
        state.routeInspected=true;
        try{
            Map<String,Object> data=new java.util.LinkedHashMap<>();
            if(attribute(request,"org.springframework.web.servlet.HandlerMapping.uriTemplateVariables") instanceof Map<?,?> params&&!params.isEmpty())data.put("server.request.path_params",WafInspector.introspect(params));
            Object contentType=request.getClass().getMethod("getContentType").invoke(request);
            if(contentType instanceof String type&&type.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded")){
                Object form=request.getClass().getMethod("getParameterMap").invoke(request);
                if(form instanceof Map<?,?> fields&&!fields.isEmpty()&&!state.bodyInspected){state.bodyInspected=true;data.put("server.request.body",WafInspector.introspect(fields));}
            }
            return decide(state,WafInspector.run(state,data),reporter)&&block(state,request,response,"rule",reporter);
        }catch(Exception|LinkageError failure){LocalAttackReporter.reportLoss("route inspection failure");return false;}
    }
    /** Fase do corpo (@RequestBody convertido): devolve true quando bloqueou e respondeu. */
    public static boolean bodyPhase(Object webRequest,Object body){
        var reporter=waf;
        if(reporter==null||body==null)return false;
        try{
            // A conversão chega aqui com o NativeWebRequest ou com a mensagem HTTP; a requisição atual vem do Spring.
            var holder=Class.forName("org.springframework.web.context.request.RequestContextHolder",false,webRequest.getClass().getClassLoader());
            Object attributes=holder.getMethod("getRequestAttributes").invoke(null);
            if(attributes==null)return false;
            Object request=JavaProtection.call(attributes,"getRequest",new Class<?>[]{});
            Object response=JavaProtection.call(attributes,"getResponse",new Class<?>[]{});
            if(request==null||response==null||!(attribute(request,STATE) instanceof WafInspector.State state)||state.blocked||state.bodyInspected)return false;
            state.bodyInspected=true;
            return decide(state,WafInspector.run(state,Map.of("server.request.body",WafInspector.introspect(body))),reporter)&&block(state,request,response,"rule",reporter);
        }catch(Exception|LinkageError failure){LocalAttackReporter.reportLoss("body inspection failure");return false;}
    }
    private static String requestMethod(Object request){try{return (String)request.getClass().getMethod("getMethod").invoke(request);}catch(ReflectiveOperationException|RuntimeException unavailable){return null;}}
    private static String requestPath(Object request){try{return (String)request.getClass().getMethod("getRequestURI").invoke(request);}catch(ReflectiveOperationException|RuntimeException unavailable){return null;}}
    public static boolean enterHandle(Object request,Object response,Object handler){
        blockedRequest.remove();
        if(response!=null&&routePhase(request,response)){previousSelection.get().push(Optional.ofNullable(selected.get()));return true;}
        Method previous=open(request,response,handler);
        previousSelection.get().push(Optional.ofNullable(previous));
        return Boolean.TRUE.equals(blockedRequest.get());
    }
    public static void exitHandle(){
        var stack=previousSelection.get();
        close(stack.isEmpty()?null:stack.pop().orElse(null));
        blockedRequest.remove();
    }
    public static Method open(Object request,Object handler){return open(request,null,handler);}
    public static Method open(Object request,Object response,Object handler){
        Method previous=selected.get();selected.remove();selectedRoute.remove();
        try{
            start();
            if(worker==null&&!Boolean.getBoolean("telvyn.iast.enabled"))return previous;
            var requestType=request.getClass();
            String verb=(String)requestType.getMethod("getMethod").invoke(request);
            Object pattern=requestType.getMethod("getAttribute",String.class).invoke(request,"org.springframework.web.servlet.HandlerMapping.bestMatchingPattern");
            if(!(pattern instanceof String route)||!routes.contains(verb+" "+route))return previous;
            Method method=(Method)handler.getClass().getMethod("getMethod").invoke(handler);
            selected.set(method);selectedRoute.set(new String[]{verb,route});
        }catch(ReflectiveOperationException|RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("Spring integration unavailable");}
        return previous;
    }
    public static void close(Method previous){if(previous==null)selected.remove();else selected.set(previous);}
    public record ReactiveScope(Method previous,Method method,boolean allowed) {}
    public static ReactiveScope reactive(Object exchange,Object handler){
        Method previous=selected.get();selected.remove();
        try{
            start();WebFluxWaf.start(exchange);if(!Boolean.getBoolean("telvyn.iast.enabled"))return new ReactiveScope(previous,null,false);
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
            if(method!=null){selected.set(method);selectedRoute.set(new String[]{verb,route});}return new ReactiveScope(previous,method,true);
        }catch(ReflectiveOperationException|RuntimeException|LinkageError failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("reactive integration unavailable");return new ReactiveScope(previous,null,false);}
    }
    static String[] trace(){
        // The application's OpenTelemetry API first; without it, the copy the OpenTelemetry Java agent keeps in the bootstrap.
        for(String prefix:new String[]{"io.opentelemetry.","io.opentelemetry.javaagent.shaded.io.opentelemetry."})try{
            var loader=prefix.startsWith("io.opentelemetry.javaagent.")?null:Thread.currentThread().getContextClassLoader();var span=Class.forName(prefix+"api.trace.Span",false,loader);
            var context=Class.forName(prefix+"api.trace.SpanContext",false,loader);
            Object current=span.getMethod("getSpanContext").invoke(span.getMethod("current").invoke(null));
            if(Boolean.TRUE.equals(context.getMethod("isValid").invoke(current)))return new String[]{(String)context.getMethod("getTraceId").invoke(current),(String)context.getMethod("getSpanId").invoke(current)};
        }catch(ReflectiveOperationException|LinkageError unavailable){ /* No valid trace context from this source. */ }
        return new String[]{null,null};
    }
    public static void jdbc(String sql,String sink){
        String prefix=System.getProperty("telvyn.iast.application-package","");
        StackWalker.getInstance().walk(frames->frames.filter(frame->!prefix.isEmpty()&&frame.getClassName().startsWith(prefix)&&!frame.getClassName().startsWith("system.monitoring.debugger.")).findFirst()).ifPresent(frame->IastRuntime.jdbc(sql,frame.getClassName()+"#"+frame.getMethodName(),frame.getLineNumber(),sink));
    }
    public static class Dispatch {
        // Requisição bloqueada: o handler do controller não roda (retorno nulo = resposta já tratada).
        @Advice.OnMethodEnter(skipOn=Advice.OnNonDefaultValue.class,suppress=Throwable.class) public static boolean enter(@Advice.Argument(0)Object request,@Advice.Argument(1)Object response,@Advice.Argument(2)Object handler){return enterHandle(request,response,handler);}
        // Bloqueio no corpo: a exceção interrompe o controller e não chega aos tratadores de erro do Spring.
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Thrown(readOnly=false)Throwable thrown){exitHandle();if(isBlock(thrown))thrown=null;}
    }
    public static class RequestPhase {
        @Advice.OnMethodEnter(skipOn=Advice.OnNonDefaultValue.class,suppress=Throwable.class) public static boolean enter(@Advice.Argument(0)Object request,@Advice.Argument(1)Object response){return requestStart(request,response);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Argument(0)Object request,@Advice.Argument(1)Object response){requestEnd(request,response);}
    }
    public static class BodyPhase {
        @Advice.OnMethodExit(onThrowable=Throwable.class) public static void exit(@Advice.Argument(0)Object webRequest,@Advice.Return Object body,@Advice.Thrown Throwable thrown){if(thrown==null&&bodyPhase(webRequest,body))throw new BlockedRequestException();}
    }
    public static class Jdbc {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(0)String sql,@Advice.Origin("#t.#m")String origin){jdbc(sql,origin);}
    }
    public static class ReactiveDispatch {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static ReactiveScope enter(@Advice.Argument(0)Object exchange,@Advice.Argument(1)Object handler){return reactive(exchange,handler);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Argument(0)Object exchange,@Advice.Enter ReactiveScope scope,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result){if(scope!=null){if(scope.method()!=null&&result!=null)result=ReactorIast.dispatch(result,scope.method());close(scope.previous());}result=WebFluxWaf.wrap(exchange,result);}
    }
    /** Endpoints funcionais do WebFlux: mesma fase de início e mesmo bloqueio. */
    public static class FunctionalDispatch {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(0)Object exchange){start();WebFluxWaf.start(exchange);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Argument(0)Object exchange,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result){result=WebFluxWaf.wrap(exchange,result);}
    }
    /** Corpo do WebFlux (@RequestBody): inspecionado quando o valor é lido; bloqueio vira erro tratado no wrap. */
    public static class ReactiveBody {
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Argument(4)Object exchange,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result){result=WebFluxWaf.body(exchange,result);}
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
