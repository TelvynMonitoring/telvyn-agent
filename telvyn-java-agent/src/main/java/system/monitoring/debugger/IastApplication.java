package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * IAST findings that need no request input:
 * the configuration of each web application (web.xml, weblogic.xml, WebSphere files, JSP layout) once per servlet
 * context, the session tracking mode once a session exists, and at the end of each inspected request the missing
 * security headers and Basic/Digest authentication. Tomcat error pages that print a stack trace are a leak.
 */
public final class IastApplication {
    private static final Map<Object,Boolean> CONTEXTS=Collections.synchronizedMap(new WeakHashMap<>());
    private static final Map<Object,Boolean> SESSIONS=Collections.synchronizedMap(new WeakHashMap<>());
    private static final ThreadLocal<int[]> DEPTH=ThreadLocal.withInitial(()->new int[1]);
    private static final Pattern MAX_AGE=Pattern.compile("max-age=(\\d+)",Pattern.CASE_INSENSITIVE);
    private static final Pattern DISPLAY_NAME=Pattern.compile("<display-name>(.*?)</display-name>");
    private static final Pattern WEBLOGIC_LISTING=Pattern.compile("<index-directory-enabled>\\s*true\\s*</index-directory-enabled>",Pattern.CASE_INSENSITIVE);
    private static final Pattern WEBSPHERE_XMI_LISTING=Pattern.compile("directoryBrowsingEnabled\\s*=\\s*\"true\"",Pattern.CASE_INSENSITIVE);
    private static final Pattern WEBSPHERE_XML_LISTING=Pattern.compile("<enable-directory-browsing\\s+value\\s*=\\s*\"true\"\\s*/>",Pattern.CASE_INSENSITIVE);
    private static final Set<String> ADMIN_CONSOLES=Set.of("Tomcat Manager Application","Tomcat Host Manager Application");
    private IastApplication() {}

    public static void install(Instrumentation instrumentation){
        if(!Boolean.getBoolean("telvyn.iast.enabled"))return;
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(namedOneOf("javax.servlet.http.HttpServlet","jakarta.servlet.http.HttpServlet"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Request.class).on(named("service").and(takesArguments(2))
                .and(takesArgument(0,namedOneOf("javax.servlet.http.HttpServletRequest","jakarta.servlet.http.HttpServletRequest"))))))
            // Servlets initialized when the application starts (the container's default servlet in every context): the
            // configuration is read even for applications that no request reaches, such as a protected admin console.
            .type(namedOneOf("javax.servlet.GenericServlet","jakarta.servlet.GenericServlet"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Init.class).on(named("init").and(takesArguments(1)))))
            .type(named("org.apache.catalina.valves.ErrorReportValve"))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(ErrorPage.class).on(named("report").and(takesArguments(3)))))
            .installOn(instrumentation);
    }

    public static class Request {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(){begin();}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.This Object servlet,@Advice.Argument(0)Object request,@Advice.Argument(1)Object response){end(servlet,request,response);}
    }
    public static class Init {
        @Advice.OnMethodExit(suppress=Throwable.class) public static void exit(@Advice.Argument(0)Object config){started(config);}
    }
    public static class ErrorPage {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(1)Object response,@Advice.Argument(2)Throwable error){errorPage(response,error);}
    }

    private static Object call(Object target,String method,Object... arguments)throws ReflectiveOperationException {
        // Container classes are often not public: the public method is called through the class that declares it.
        for(var candidate:target.getClass().getMethods())if(candidate.getName().equals(method)&&candidate.getParameterCount()==arguments.length){candidate.trySetAccessible();return candidate.invoke(target,arguments);}
        throw new NoSuchMethodException(method);
    }
    private static String header(Object response,String name)throws ReflectiveOperationException {return (String)call(response,"getHeader",name);}

    public static void started(Object config){
        try{if(config!=null)application(call(config,"getServletContext"));}
        catch(ReflectiveOperationException|RuntimeException|LinkageError unavailable){LocalAttackReporter.reportLoss("IAST application unavailable");}
    }
    // Once per servlet context, at its first servlet initialization or its first request.
    private static void application(Object context)throws ReflectiveOperationException {
        if(context==null||CONTEXTS.putIfAbsent(context,Boolean.TRUE)!=null)return;
        // Several applications share a container: the location starts with the context path ("" for the root one).
        String path=String.valueOf(call(context,"getContextPath")).replaceAll("^/+","").replaceAll("[^A-Za-z0-9_./-]","_");
        onRealPath((String)call(context,"getRealPath","/"),path.isEmpty()||path.length()>100||path.contains("..")?"":path+"/");
    }
    // Advice code is copied into the servlet class: what it calls must be public.
    public static void begin(){DEPTH.get()[0]++;}
    // Forwards and includes run service again: only the outermost call ends the request.
    public static void end(Object servlet,Object request,Object response){if(--DEPTH.get()[0]==0)requestEnd(servlet,request,response);}
    static void requestEnd(Object servlet,Object request,Object response){
        try{
            SpringMvcSecurity.start();
            if(!IastRuntime.active())return;
            Object context=call(request,"getServletContext");
            application(context);
            if(context!=null&&!SESSIONS.containsKey(context)&&call(request,"getSession",false)!=null){
                SESSIONS.put(context,Boolean.TRUE);
                Object modes=call(context,"getEffectiveSessionTrackingModes");
                if(modes instanceof Collection<?> list)for(Object mode:list)if("URL".equals(String.valueOf(mode)))
                    IastRuntime.once("SESSION_REWRITING",context.getClass().getName().startsWith("jakarta.")?"jakarta.servlet.ServletContext#getEffectiveSessionTrackingModes":"javax.servlet.ServletContext#getEffectiveSessionTrackingModes",0,null);
            }
            // Request checks only on the routes selected for IAST, like every other class.
            String verb=(String)call(request,"getMethod"),path=(String)call(request,"getServletPath");
            Object extra=call(request,"getPathInfo");
            if(extra instanceof String info)path+=info;
            if(!SpringMvcSecurity.servletSelected(verb,path))return;
            int status=(Integer)call(response,"getStatus");
            String location=servlet.getClass().getName()+"#service";
            String authorization=(String)call(request,"getHeader","Authorization");
            // Credentials sent to a page that failed (scanners) are not judged.
            if(authorization!=null&&status<400&&(authorization.startsWith("Basic")||authorization.startsWith("Digest")))IastRuntime.once("INSECURE_AUTH_PROTOCOL",location,0,null);
            if(ignorable(status)||!html((String)call(response,"getContentType")))return;
            String options=header(response,"X-Content-Type-Options");
            if(options==null||!options.toLowerCase(Locale.ROOT).contains("nosniff"))IastRuntime.once("XCONTENTTYPE_HEADER_MISSING",location,0,null);
            String forwarded=(String)call(request,"getHeader","X-Forwarded-Proto");
            boolean https=String.valueOf(call(request,"getRequestURL")).toLowerCase(Locale.ROOT).startsWith("https://")||forwarded!=null&&forwarded.toLowerCase(Locale.ROOT).contains("https");
            if(https&&!validMaxAge(header(response,"Strict-Transport-Security")))IastRuntime.once("HSTS_HEADER_MISSING",location,0,null);
        }catch(ReflectiveOperationException|RuntimeException|LinkageError unavailable){LocalAttackReporter.reportLoss("IAST request end unavailable");}
    }
    static boolean html(String contentType){
        if(contentType==null)return false;
        String type=contentType.toLowerCase(Locale.ROOT);
        return type.contains("text/html")||type.contains("application/xhtml+xml");
    }
    // Redirects, not modified, not found, gone and server errors are not judged.
    static boolean ignorable(int status){return status==301||status==302||status==304||status==307||status==404||status==410||status==500;}
    static boolean validMaxAge(String value){
        if(value==null)return false;
        Matcher matcher=MAX_AGE.matcher(value);
        try{return matcher.find()&&Long.parseLong(matcher.group(1))>0;}catch(NumberFormatException huge){return true;}
    }

    // Tomcat's error page with the exception of the request (status 4xx/5xx other than 404, marked as an error).
    public static void errorPage(Object response,Throwable error){
        try{
            if(error==null||!IastRuntime.active())return;
            int status=(Integer)call(response,"getStatus");
            if(status<400||status==404||!Boolean.TRUE.equals(call(response,"isError")))return;
            IastRuntime.once("STACKTRACE_LEAK","org.apache.catalina.valves.ErrorReportValve#report",0,"org.apache.catalina.valves.ErrorReportValve.report");
        }catch(ReflectiveOperationException|RuntimeException|LinkageError unavailable){LocalAttackReporter.reportLoss("IAST error page unavailable");}
    }

    // Configuration of the web application, read from its directory once per servlet context.
    static void onRealPath(String realPath,String application){
        if(realPath==null)return;
        Path root=Paths.get(realPath);
        if(!Files.isDirectory(root))return;
        insecureJspLayout(root,application);
        String webXml=read(root,"web.xml");
        if(webXml!=null)webXml(webXml,application);
        String weblogic=read(root,"weblogic.xml");
        if(weblogic!=null)matchAll(weblogic,WEBLOGIC_LISTING,application+"WEB-INF/weblogic.xml#index-directory-enabled");
        String xmi=read(root,"ibm-web-ext.xmi");
        if(xmi!=null)matchAll(xmi,WEBSPHERE_XMI_LISTING,application+"WEB-INF/ibm-web-ext.xmi#directoryBrowsingEnabled");
        String websphere=read(root,"ibm-web-ext.xml");
        if(websphere!=null)matchAll(websphere,WEBSPHERE_XML_LISTING,application+"WEB-INF/ibm-web-ext.xml#enable-directory-browsing");
    }
    private static String read(Path root,String name){
        try{Path file=root.resolve("WEB-INF").resolve(name);return Files.isRegularFile(file)?Files.readString(file,StandardCharsets.UTF_8):null;}
        catch(java.io.IOException|RuntimeException unreadable){return null;}
    }
    private static int line(String text,int index){int line=1;for(int i=0;i<index&&i<text.length();i++)if(text.charAt(i)=='\n')line++;return line;}
    private static void matchAll(String text,Pattern pattern,String location){
        Matcher matcher=pattern.matcher(text);
        while(matcher.find())IastRuntime.once("DIRECTORY_LISTING_LEAK",location,line(text,matcher.start()),null);
    }
    private static String between(String text,int from,String end){int stop=text.indexOf(end,from);return stop<0?null:text.substring(from,stop).trim();}
    static void webXml(String xml,String application){
        // Session timeout above 30 minutes or without expiration.
        for(int index=xml.indexOf("<session-timeout>");index>=0;index=xml.indexOf("<session-timeout>",index+1)){
            String value=between(xml,index+"<session-timeout>".length(),"</session-timeout>");
            try{int minutes=Integer.parseInt(value);if(minutes>30||minutes==-1)IastRuntime.once("SESSION_TIMEOUT",application+"WEB-INF/web.xml#session-timeout",line(xml,index),null);}
            catch(NumberFormatException|NullPointerException notNumber){ /* Not a number: not judged. */ }
        }
        // Directory listings on the default servlet (Tomcat listings, Jetty dirAllowed).
        for(String parameter:new String[]{"<param-name>listings</param-name>","<param-name>dirAllowed</param-name>"})
            for(int index=xml.indexOf(parameter);index>=0;index=xml.indexOf(parameter,index+1)){
                int start=xml.indexOf("<param-value>",index);
                String value=start<0?null:between(xml,start+"<param-value>".length(),"</param-value>");
                if("true".equalsIgnoreCase(value))IastRuntime.once("DIRECTORY_LISTING_LEAK",application+"WEB-INF/web.xml#"+(parameter.contains("listings")?"listings":"dirAllowed"),line(xml,index),null);
            }
        // A security constraint without http-method.
        for(int index=xml.indexOf("<security-constraint>");index>=0;index=xml.indexOf("<security-constraint>",index+1)){
            String inner=between(xml,index+"<security-constraint>".length(),"</security-constraint>");
            if(inner!=null&&!inner.contains("<http-method>"))IastRuntime.once("VERB_TAMPERING",application+"WEB-INF/web.xml#security-constraint",line(xml,index),null);
        }
        // Spring applications: defaultHtmlEscape must be set to true.
        if(xml.contains("org.springframework.web.context.ContextLoaderListener")||xml.contains("org.springframework.web.servlet.DispatcherServlet")){
            int index=xml.lastIndexOf("defaultHtmlEscape");
            if(index<0)IastRuntime.once("DEFAULT_HTML_ESCAPE_INVALID",application+"WEB-INF/web.xml#defaultHtmlEscape",0,null);
            else{
                int start=xml.indexOf("<param-value>",index);
                String value=start<0?null:between(xml,start+"<param-value>".length(),"</param-value>");
                if(!"true".equalsIgnoreCase(value))IastRuntime.once("DEFAULT_HTML_ESCAPE_INVALID",application+"WEB-INF/web.xml#defaultHtmlEscape",line(xml,start<0?index:start),null);
            }
        }
        // Tomcat's administration consoles deployed.
        Matcher name=DISPLAY_NAME.matcher(xml);
        while(name.find())if(ADMIN_CONSOLES.contains(name.group(1)))IastRuntime.once("ADMIN_CONSOLE_ACTIVE",application+"WEB-INF/web.xml#display-name",line(xml,name.start()),null);
    }
    // JSP files outside WEB-INF can be requested directly: one finding per folder that has them.
    static void insecureJspLayout(Path root,String application){
        var folders=new LinkedHashMap<Path,Path>();
        try{
            Files.walkFileTree(root,EnumSet.noneOf(FileVisitOption.class),32,new SimpleFileVisitor<>(){
                @Override public FileVisitResult preVisitDirectory(Path dir,java.nio.file.attribute.BasicFileAttributes attributes){
                    return dir.getFileName()!=null&&dir.getFileName().toString().toUpperCase(Locale.ROOT).endsWith("WEB-INF")?FileVisitResult.SKIP_SUBTREE:FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult visitFile(Path file,java.nio.file.attribute.BasicFileAttributes attributes){
                    String name=file.getFileName().toString().toLowerCase(Locale.ROOT);
                    if(!name.endsWith(".jsp")&&!name.endsWith(".jspx"))return FileVisitResult.CONTINUE;
                    folders.putIfAbsent(file.getParent(),file);
                    return folders.size()>=16?FileVisitResult.TERMINATE:FileVisitResult.SKIP_SIBLINGS;
                }
                @Override public FileVisitResult visitFileFailed(Path file,java.io.IOException failure){return FileVisitResult.CONTINUE;}
            });
        }catch(java.io.IOException|RuntimeException unreadable){return;}
        for(Path file:folders.values()){
            String relative=root.relativize(file).toString().replace('\\','/').replaceAll("[^A-Za-z0-9_./-]","_");
            if(relative.length()<=200&&!relative.contains(".."))IastRuntime.once("INSECURE_JSP_LAYOUT",application+relative+"#jsp",0,null);
        }
    }
}
