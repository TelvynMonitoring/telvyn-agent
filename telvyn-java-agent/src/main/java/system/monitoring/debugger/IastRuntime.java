package system.monitoring.debugger;

import java.lang.invoke.*;
import java.lang.reflect.Method;
import java.util.IdentityHashMap;
import java.util.function.Consumer;

/** Request-local provenance. Values never cross into a finding or the export queue. */
public final class IastRuntime {
    public record Finding(String method,Integer line,long elapsedUs,String rulesVersion,String sink,String sql,java.util.List<String> stack,String ruleId,String source) {}
    private static volatile Consumer<Finding> reporter;
    private static volatile java.util.function.Predicate<Method> configuredSources=method->false;
    private static final ThreadLocal<State> current=new ThreadLocal<>();
    private static volatile java.util.function.Supplier<String[]> traceSource=()->null;
    // Method and route template of the request (never the concrete path: a route parameter is input).
    private static volatile java.util.function.Supplier<String[]> requestSource=()->null;
    private static final class State {
        final java.util.Map<Object,String> tainted=java.util.Collections.synchronizedMap(new IdentityHashMap<>());
        final String[] trace=traceSource.get();
        String[] request=requestSource.get();
        final java.util.Set<Object> writers=java.util.Collections.newSetFromMap(java.util.Collections.synchronizedMap(new IdentityHashMap<>()));
        final long started=System.nanoTime();
        final java.util.Set<String> reported=new java.util.HashSet<>(); volatile boolean closed;
    }
    private IastRuntime() {}
    public static void configure(Consumer<Finding> sink){reporter=sink;SecuritySensorState.iastIntegration(sink!=null);}
    public static void configureSources(java.util.function.Predicate<Method> sources){configuredSources=sources==null?method->false:sources;}
    public static void configureTrace(java.util.function.Supplier<String[]> source){traceSource=source==null?()->null:source;}
    public static void configureRequest(java.util.function.Supplier<String[]> source){requestSource=source==null?()->null:source;}
    public static String[] request(){var state=current.get();return state==null?null:state.request;}
    public static String[] traceIds(){var state=current.get();return state==null?null:state.trace;}
    public static Object capture(){return current.get();}
    public static void restore(Object context){if(context instanceof State state&&!state.closed)current.set(state);else current.remove();}
    public static void release(Object context){if(context instanceof State state)synchronized(state){state.closed=true;state.tainted.clear();}}
    public static Object beginFunctional(){return reporter==null?null:new State();}
    public static void functionalParameters(Object result){
        if(current.get()!=null&&result instanceof java.util.Map<?,?> values&&values.get("q") instanceof java.util.List<?> entries&&entries.size()==1)functionalParameter("q",java.util.Optional.ofNullable(entries.get(0)));
    }
    public static void functionalParameter(String name,Object result){
        var state=current.get();
        if(state==null||!"q".equals(name)||!(result instanceof java.util.Optional<?> optional)||!(optional.orElse(null) instanceof String value)||value.isEmpty())return;
        synchronized(state){if(state.closed)return;if(value.length()<=2048&&(state.tainted.size()<256||state.tainted.containsKey(value)))state.tainted.put(value,"query:q");else LocalAttackReporter.reportLoss("IAST source limit");}
    }
    public static Object enter(Method method,Object[] arguments) {
        State previous=current.get();
        if(reporter==null)return previous;
        String result=method.getReturnType().getName();
        if(!method.getReturnType().equals(String.class)&&!result.equals("jakarta.ws.rs.core.Response")&&!result.equals("org.springframework.http.ResponseEntity")&&!java.util.List.class.isAssignableFrom(method.getReturnType())&&!result.equals("java.util.concurrent.Callable")&&!java.util.concurrent.CompletionStage.class.isAssignableFrom(method.getReturnType())&&!result.equals("org.springframework.web.context.request.async.DeferredResult")&&!result.equals("org.springframework.web.context.request.async.WebAsyncTask")&&!result.equals("reactor.core.publisher.Mono")&&!result.equals("reactor.core.publisher.Flux"))return previous;
        try {
            boolean routeSelected=configuredSources.test(method);
            java.util.Set<String> inspected=new java.util.HashSet<>();
            for(var annotation:method.getAnnotations())if(annotation.annotationType().getName().equals("system.monitoring.security.InspectQuery"))
                inspected.addAll(java.util.Arrays.asList((String[])annotation.annotationType().getMethod("value").invoke(annotation)));
            if(!routeSelected&&inspected.isEmpty())return previous;
            State state=new State();current.set(state);
            var parameters=method.getParameters();
            var annotations=method.getParameterAnnotations();
            for(int i=0;i<annotations.length;i++)for(var annotation:annotations[i]) {
                String kind=sourceKind(annotation.annotationType().getName());
                if(kind==null||!(arguments[i] instanceof String value)||value.isEmpty())continue;
                String name=sourceName(annotation,parameters[i]);
                // A configured route exposes every supported input; the annotation only exposes the query names it lists.
                if(!routeSelected&&!(kind.equals("query")&&inspected.contains(name)))continue;
                if(value.length()>2048||state.tainted.size()>=256){LocalAttackReporter.reportLoss("IAST source limit");continue;}
                state.tainted.put(value,kind+":"+name);
            }
        }catch(ReflectiveOperationException failure){LocalAttackReporter.reportLoss("IAST source unavailable");}
        return previous;
    }
    private static String sourceKind(String annotation){
        return switch(annotation){
            case "org.springframework.web.bind.annotation.RequestParam","jakarta.ws.rs.QueryParam"->"query";
            case "org.springframework.web.bind.annotation.PathVariable","jakarta.ws.rs.PathParam"->"path";
            case "org.springframework.web.bind.annotation.RequestHeader","jakarta.ws.rs.HeaderParam"->"header";
            case "org.springframework.web.bind.annotation.CookieValue","jakarta.ws.rs.CookieParam"->"cookie";
            default->null;
        };
    }
    // Only the name of the input is reported, never its value; the name is limited to what the backend accepts.
    private static String sourceName(java.lang.annotation.Annotation annotation,java.lang.reflect.Parameter parameter)throws ReflectiveOperationException {
        String name=null;
        for(String attribute:new String[]{"value","name"}) {
            try{if(annotation.annotationType().getMethod(attribute).invoke(annotation) instanceof String text&&!text.isBlank()){name=text;break;}}
            catch(NoSuchMethodException absent){ /* This annotation has no such attribute. */ }
        }
        if(name==null)name=parameter.getName();
        String clean=name.replaceAll("[^A-Za-z0-9_.-]","_");
        return clean.length()>64?clean.substring(0,64):clean;
    }
    public static void exit(Object previous){if(previous==null)current.remove();else current.set((State)previous);}
    // A servlet request of a selected route: every input read through the servlet API below is a source.
    public static Object openRequest(){return openRequest(null,null);}
    public static Object openRequest(String method,String route){State previous=current.get();if(reporter!=null){State state=new State();if(method!=null)state.request=new String[]{method,route};current.set(state);}return previous;}
    private static String clean(String name){String text=name==null||name.isBlank()?"unnamed":name.replaceAll("[^A-Za-z0-9_.-]","_");return text.length()>64?text.substring(0,64):text;}
    private static void mark(Object value,String kind,String name){
        var state=current.get();
        if(state==null||!(value instanceof String text)||text.isEmpty())return;
        synchronized(state){if(state.closed)return;if(text.length()<=2048&&(state.tainted.size()<256||state.tainted.containsKey(text)))state.tainted.put(text,kind+":"+clean(name));else LocalAttackReporter.reportLoss("IAST source limit");}
    }
    public static String sourceParameter(String name,String value){mark(value,"parameter",name);return value;}
    public static String sourceHeader(String name,String value){mark(value,"header",name);return value;}
    public static String sourceQuery(String value){mark(value,"query","querystring");return value;}
    public static String[] sourceParameterValues(String name,String[] values){if(values!=null&&current.get()!=null)for(String value:values)mark(value,"parameter",name);return values;}
    public static java.util.Map<?,?> sourceParameterMap(java.util.Map<?,?> values){
        if(values!=null&&current.get()!=null)for(var entry:values.entrySet())if(entry.getValue() instanceof String[] list&&entry.getKey() instanceof String name)for(String value:list)mark(value,"parameter",name);
        return values;
    }
    public static java.util.Enumeration<?> sourceHeaders(String name,java.util.Enumeration<?> values){
        if(values==null||current.get()==null)return values;
        var list=java.util.Collections.list(values);for(Object value:list)mark(value,"header",name);
        return java.util.Collections.enumeration(list);
    }
    // Names are input too: a parameter or header name comes from the request. Only the kind is reported, never the name.
    public static java.util.Enumeration<?> sourceNames(String kind,java.util.Enumeration<?> names){
        if(names==null||current.get()==null)return names;
        var list=java.util.Collections.list(names);for(Object name:list)mark(name,kind,"names");
        return java.util.Collections.enumeration(list);
    }
    // One-argument transformations (decoding, bytes, characters, Base64, split): the result keeps the origin of its input.
    public static Object propagateFrom(Object source,Object result){
        if(current.get()==null||source==null||result==null)return result;
        if(result instanceof Object[] items)for(Object item:items)propagate(source,item);
        propagate(source,result);
        return result;
    }
    private static final ClassValue<Method> COOKIE_NAME=new ClassValue<>(){@Override protected Method computeValue(Class<?> type){try{return type.getMethod("getName");}catch(NoSuchMethodException absent){return null;}}};
    public static String sourceCookie(Object cookie,String value){
        if(cookie==null||current.get()==null)return value;
        try{Method name=COOKIE_NAME.get(cookie.getClass());if(name!=null)mark(value,"cookie",(String)name.invoke(cookie));}
        catch(ReflectiveOperationException|ClassCastException unavailable){LocalAttackReporter.reportLoss("IAST source unavailable");}
        return value;
    }
    private static boolean tainted(Object value){var s=current.get();return s!=null&&s.tainted.containsKey(value);}
    // An origin escaped for HTML carries this mark: it still counts for every class except XSS.
    private static final String XSS_SAFE="#xss";
    private static String origin(String label){return label==null?null:label.endsWith(XSS_SAFE)?label.substring(0,label.length()-XSS_SAFE.length()):label;}
    private static void propagate(Object source,Object target){
        var s=current.get();if(s==null||!tainted(source))return;
        synchronized(s){
            if(s.closed)return;
            // When parts meet (concatenation, a builder), an origin that was not escaped wins over one that was.
            String existing=s.tainted.get(target);
            if(existing!=null&&!existing.endsWith(XSS_SAFE))return;
            if((!(target instanceof String value)||value.length()<=8192)&&s.tainted.size()<256)s.tainted.put(target,s.tainted.get(source));else LocalAttackReporter.reportLoss("IAST propagation limit");
        }
    }
    // HTML escaping (StringEscapeUtils, ESAPI encodeForHTML, HtmlUtils, OWASP Encoder): the result keeps the origin, marked safe for XSS only.
    public static Object sanitizeXss(Object source,Object result){
        var s=current.get();if(s==null||result==null||!tainted(source))return result;
        synchronized(s){if(!s.closed&&s.tainted.size()<256)s.tainted.put(result,origin(s.tainted.get(source))+XSS_SAFE);}
        return result;
    }
    public static String concat(String left,String right){String result=left.concat(right);propagate(left,result);propagate(right,result);return result;}
    public static String trim(String value){String result=value.trim();propagate(value,result);return result;}
    public static String toLowerCase(String value){String result=value.toLowerCase();propagate(value,result);return result;}
    public static String toUpperCase(String value){String result=value.toUpperCase();propagate(value,result);return result;}
    public static String strip(String value){String result=value.strip();propagate(value,result);return result;}
    public static String substring(String value,int from){String result=value.substring(from);propagate(value,result);return result;}
    public static String substring(String value,int from,int to){String result=value.substring(from,to);propagate(value,result);return result;}
    public static String replace(String value,CharSequence target,CharSequence replacement){String result=value.replace(target,replacement);propagate(value,result);propagate(replacement,result);return result;}
    public static StringBuilder append(StringBuilder builder,String text){builder.append(text);propagate(text,builder);return builder;}
    public static StringBuffer append(StringBuffer builder,String text){builder.append(text);propagate(text,builder);return builder;}
    public static String builderToString(StringBuilder builder){String result=builder.toString();propagate(builder,result);return result;}
    public static String bufferToString(StringBuffer builder){String result=builder.toString();propagate(builder,result);return result;}
    public static CallSite concatFactory(MethodHandles.Lookup lookup,String name,MethodType type,String recipe,Object... constants)throws Throwable {
        var original=StringConcatFactory.makeConcatWithConstants(lookup,name,type,recipe,constants).getTarget();
        var spread=original.asSpreader(Object[].class,type.parameterCount());
        var wrapper=MethodHandles.lookup().findStatic(IastRuntime.class,"concatenate",MethodType.methodType(String.class,MethodHandle.class,Object[].class));
        return new ConstantCallSite(wrapper.bindTo(spread).asCollector(Object[].class,type.parameterCount()).asType(type));
    }
    private static String concatenate(MethodHandle original,Object[] arguments)throws Throwable {
        String result=(String)original.invoke(arguments);
        for(Object argument:arguments)propagate(argument,result);
        return result;
    }
    public static void jdbc(String sql,String method,int line,String sink){
        query(sql,method,line,"iast-q-jdbc-1",sink);
    }
    public static void r2dbc(String sql,String method,int line,String sink){query(sql,method,line,"iast-q-r2dbc-1",sink);}
    public static java.util.function.Supplier<String> r2dbcSupplier(java.util.function.Supplier<String> supplier,String method,int line,String sink){
        if(supplier==null)return null;
        // Preserve PreparedOperation.bindTo and inspect only SQL requested by DatabaseClient.
        try{
            var prepared=Class.forName("org.springframework.r2dbc.core.PreparedOperation",false,supplier.getClass().getClassLoader());
            if(prepared.isInstance(supplier))return (java.util.function.Supplier<String>)java.lang.reflect.Proxy.newProxyInstance(prepared.getClassLoader(),new Class<?>[]{prepared},(proxy,called,args)->{
                try{Object result=called.invoke(supplier,args);if((called.getName().equals("get")||called.getName().equals("toQuery"))&&result instanceof String sql)r2dbc(sql,method,line,sink);return result;}
                catch(java.lang.reflect.InvocationTargetException failure){throw failure.getCause();}
            });
        }
        catch(ClassNotFoundException unavailable){ /* No PreparedOperation API in this application. */ }
        return ()->{String sql=supplier.get();r2dbc(sql,method,line,sink);return sql;};
    }
    public static void orm(String hql,String method,int line,String sink){
        query(hql,method,line,"iast-q-orm-1",sink);
    }
    private static void query(String sql,String method,int line,String rulesVersion,String sink){
        try {
            var state=current.get();var report=reporter;
            if(state==null||report==null)return;
            String source;
            synchronized(state){if(state.closed||!tainted(sql)||!state.reported.add("SQL_INJECTION"))return;source=origin(state.tainted.get(sql));}
            report.accept(new Finding(method,line>0?line:null,(System.nanoTime()-state.started)/1000,rulesVersion,sinkLabel(sink),SqlMask.mask(sql),stack(),"SQL_INJECTION",source));
        }catch(RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("IAST report failure");}
    }
    public static void command(Object value,String method,int line,String sink){flaw(value,method,line,sink,"COMMAND_INJECTION");}
    public static void command(Object command,Object environment,String method,int line,String sink){flaw(new Object[]{command,environment},method,line,sink,"COMMAND_INJECTION");}
    public static void path(Object value,String method,int line,String sink){flaw(value,method,line,sink,"PATH_TRAVERSAL");}
    public static void path(Object first,Object second,String method,int line,String sink){flaw(new Object[]{first,second},method,line,sink,"PATH_TRAVERSAL");}
    // A file: URI never leaves the host: it is a path (checked where the file is opened), not a server-side request.
    public static void ssrf(Object value,String method,int line,String sink){
        if(value instanceof String text&&text.regionMatches(true,0,"file:",0,5))return;
        flaw(value,method,line,sink,"SSRF");
    }
    private static void flaw(Object value,String method,int line,String sink,String rule){
        try {
            var state=current.get();var report=reporter;
            if(state==null||report==null)return;
            Object found=taintedPart(value,0,rule.equals("XSS"));
            if(found==null)return;
            String source;
            synchronized(state){if(state.closed||!state.reported.add(rule+"@"+method+":"+line))return;source=origin(state.tainted.get(found));}
            report.accept(new Finding(method,line>0?line:null,(System.nanoTime()-state.started)/1000,"iast-q-jvm-sinks-1",sinkLabel(sink),null,stack(),rule,source));
        }catch(RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("IAST report failure");}
    }
    public static void code(Object value,String method,int line,String sink){flaw(value,method,line,sink,"CODE_INJECTION");}
    // Only the writer of the HTTP response is an XSS sink; writers of files and logs are not.
    public static Object responseWriter(Object writer){var state=current.get();if(state!=null&&writer!=null&&state.writers.size()<16)state.writers.add(writer);return writer;}
    public static void xss(Object writer,Object value,String method,int line,String sink){var state=current.get();if(state!=null&&writer!=null&&state.writers.contains(writer))flaw(value,method,line,sink,"XSS");}
    public static void ldap(Object filter,String method,int line,String sink){flaw(filter,method,line,sink,"LDAP_INJECTION");}
    public static void xpath(Object expression,String method,int line,String sink){flaw(expression,method,line,sink,"XPATH_INJECTION");}
    // Request input stored in the session, under its name or as its value, crosses the trust boundary.
    public static void trustBoundary(Object name,Object value,String method,int line,String sink){flaw(new Object[]{name,value},method,line,sink,"TRUST_BOUNDARY_VIOLATION");}
    public static void weakRandom(String method,int line,String sink){withoutInput(method,line,sink,"WEAK_RANDOMNESS");}
    public static void nosql(Object value,String method,int line,String sink){flaw(value,method,line,sink,"NOSQL_INJECTION");}
    public static void redirect(Object value,String method,int line,String sink){flaw(value,method,line,sink,"UNVALIDATED_REDIRECT");}
    public static void header(Object value,String method,int line,String sink){flaw(value,method,line,sink,"HEADER_INJECTION");}
    // Weak algorithms and unprotected cookies need no input: they count only inside a request that was selected for inspection.
    private static final java.util.Set<String> WEAK_HASHES=java.util.Set.of("MD2","MD4","MD5","SHA","SHA1","SHA-1");
    private static final java.util.Set<String> WEAK_CIPHERS=java.util.Set.of("DES","RC2","RC4","ARCFOUR","BLOWFISH");
    private static final java.util.Set<String> DEFAULT_ECB=java.util.Set.of("AES","DES","DESEDE","BLOWFISH","RC2");
    public static void weakHash(Object algorithm,String method,int line,String sink){
        if(algorithm instanceof String name&&WEAK_HASHES.contains(name.trim().toUpperCase(java.util.Locale.ROOT)))withoutInput(method,line,sink,"WEAK_HASH");
    }
    public static void weakCipher(Object transformation,String method,int line,String sink){
        if(!(transformation instanceof String text))return;
        String[] parts=text.trim().toUpperCase(java.util.Locale.ROOT).split("/",-1);
        // A bare block cipher name uses the provider default, which is ECB.
        // ECB is a weakness of block ciphers; for RSA the JCA name "RSA/ECB/..." is historical (one block, no chaining).
        boolean blockEcb=parts.length>1&&parts[1].equals("ECB")&&!parts[0].startsWith("RSA");
        if(WEAK_CIPHERS.contains(parts[0])||blockEcb||parts.length==1&&DEFAULT_ECB.contains(parts[0]))withoutInput(method,line,sink,"WEAK_CIPHER");
    }
    public static void cookie(Object cookie,String method,int line,String sink){
        if(cookie==null)return;
        try {
            var type=cookie.getClass();
            if((Integer)type.getMethod("getMaxAge").invoke(cookie)==0)return;
            if(!(Boolean)type.getMethod("getSecure").invoke(cookie))withoutInput(method,line,sink,"INSECURE_COOKIE");
            if(!(Boolean)type.getMethod("isHttpOnly").invoke(cookie))withoutInput(method,line,sink,"NO_HTTPONLY_COOKIE");
            // SameSite can be set on the cookie object only from Servlet 6; before that it travels in the header, so absence is not judged here.
            try{Object sameSite=type.getMethod("getAttribute",String.class).invoke(cookie,"SameSite");if(sameSite==null||sameSite.toString().isEmpty())withoutInput(method,line,sink,"NO_SAMESITE_COOKIE");}
            catch(NoSuchMethodException older){ /* Servlet before 6. */ }
        }catch(ReflectiveOperationException|RuntimeException failure){LocalAttackReporter.reportLoss("IAST cookie inspection unavailable");}
    }
    private static void withoutInput(String method,int line,String sink,String rule){
        try {
            var state=current.get();var report=reporter;
            if(state==null||report==null)return;
            synchronized(state){if(state.closed||!state.reported.add(rule+"@"+method+":"+line))return;}
            report.accept(new Finding(method,line>0?line:null,(System.nanoTime()-state.started)/1000,"iast-jvm-flaws-1",sinkLabel(sink),null,stack(),rule,null));
        }catch(RuntimeException|LinkageError failure){LocalAttackReporter.reportLoss("IAST report failure");}
    }
    // The tainted value itself, or the first tainted element when a command or path arrives as an array or a list.
    private static Object taintedPart(Object value,int depth){return taintedPart(value,depth,false);}
    private static Object taintedPart(Object value,int depth,boolean xss){
        if(value==null||depth>2)return null;
        if(tainted(value)&&!(xss&&String.valueOf(current.get().tainted.get(value)).endsWith(XSS_SAFE)))return value;
        if(value instanceof Object[] items){for(Object item:items){Object found=taintedPart(item,depth+1,xss);if(found!=null)return found;}}
        else if(value instanceof Iterable<?> items){for(Object item:items){Object found=taintedPart(item,depth+1,xss);if(found!=null)return found;}}
        return null;
    }
    // The instrumented API (for example java.sql.Statement.executeQuery), restricted to what the backend accepts.
    private static String sinkLabel(String sink){
        if(sink==null)return null;
        String clean=sink.replaceAll("[^A-Za-z0-9_.]","_");
        return clean.length()>80?clean.substring(0,80):clean;
    }
    // Call stack at the sink: class, method, file and line only; never a value. Agent frames are left out.
    private static java.util.List<String> stack(){
        try{
            return StackWalker.getInstance().walk(frames->frames
                .filter(frame->!frame.getClassName().startsWith("system.monitoring.debugger."))
                .limit(64)
                .map(frame->{
                    String file=frame.getFileName()==null?"Unknown Source":frame.getFileName();
                    String text=frame.getClassName()+"."+frame.getMethodName()+" ("+file+(frame.getLineNumber()>0?":"+frame.getLineNumber():"")+")";
                    return text.length()>300?text.substring(0,300):text;
                })
                .collect(java.util.stream.Collectors.toList()));
        }catch(RuntimeException failure){return java.util.List.of();}
    }
}
