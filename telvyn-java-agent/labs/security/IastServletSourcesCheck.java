package system.monitoring.securitylab;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import system.monitoring.debugger.IastRuntime;
import java.io.File;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

/**
 * Focused diagnostic for the servlet inputs (HttpServletRequest read directly, as plain servlets and OWASP Benchmark do).
 * Run with assertions and the agent in iast-only mode; nothing is read from disk, files do not exist.
 */
public class IastServletSourcesCheck {
    static String token(String name){return new String("tainted-"+name);}
    // The request answers every read with a fresh String, the way a container builds them.
    static final HttpServletRequest REQUEST=(HttpServletRequest)Proxy.newProxyInstance(IastServletSourcesCheck.class.getClassLoader(),new Class<?>[]{HttpServletRequest.class},(proxy,method,arguments)->switch(method.getName()){
        case "getParameter"->token("p");
        case "getHeader"->token("h");
        case "getParameterValues"->new String[]{token("v1"),token("v2")};
        case "getParameterMap"->Map.of("m",new String[]{token("m")});
        case "getHeaders"->Collections.enumeration(java.util.List.of(token("hs")));
        case "getQueryString"->token("q");
        case "getParameterNames"->Collections.enumeration(java.util.List.of(token("pn")));
        case "getHeaderNames"->Collections.enumeration(java.util.List.of(token("hn")));
        default->null;
    });
    static void parameter(){new File("/telvyn-nonexistent/"+REQUEST.getParameter("name"));}
    static void header(){new File("/telvyn-nonexistent/"+REQUEST.getHeader("X-Name"));}
    static void values(){for(String value:REQUEST.getParameterValues("list"))new File("/telvyn-nonexistent/"+value);}
    static void map(){new File("/telvyn-nonexistent/"+REQUEST.getParameterMap().get("m")[0]);}
    static void headers(){var e=REQUEST.getHeaders("X-Multi");while(e.hasMoreElements())new File("/telvyn-nonexistent/"+e.nextElement());}
    static void query(){new File("/telvyn-nonexistent/"+REQUEST.getQueryString());}
    static void cookie(){new File("/telvyn-nonexistent/"+new Cookie("sid",token("c")).getValue());}
    // Transformations between the read and the sink: decoding, bytes, characters, Base64, split.
    static void decoded()throws Exception{new File("/telvyn-nonexistent/"+java.net.URLDecoder.decode(REQUEST.getParameter("d"),"UTF-8"));}
    static void bytes(){new File("/telvyn-nonexistent/"+new String(REQUEST.getParameter("b").getBytes()));}
    static void base64(){var b64=java.util.Base64.getDecoder().decode(java.util.Base64.getEncoder().encode(REQUEST.getParameter("e").getBytes(java.nio.charset.StandardCharsets.UTF_8)));new File("/telvyn-nonexistent/"+new String(b64,java.nio.charset.StandardCharsets.UTF_8));}
    static void chars(){new File("/telvyn-nonexistent/"+String.valueOf(REQUEST.getParameter("c").toCharArray()));}
    static void split(){new File("/telvyn-nonexistent/"+REQUEST.getParameter("s").split(",")[0]);}
    static void names(){
        var e=REQUEST.getParameterNames();new File("/telvyn-nonexistent/"+e.nextElement());
        var h=REQUEST.getHeaderNames();new File("/telvyn-nonexistent/"+h.nextElement());
    }
    static void safeTransform()throws Exception{new File("/telvyn-nonexistent/"+java.net.URLDecoder.decode(new String("constant".getBytes()),"UTF-8"));}
    static void expect(boolean condition,String message){if(!condition)throw new AssertionError(message);}
    public static void main(String[] args)throws Exception{
        var findings=new ArrayList<IastRuntime.Finding>();
        IastRuntime.configure(findings::add);
        Object previous=IastRuntime.openRequest();
        parameter();header();values();map();headers();query();cookie();
        var sources=findings.stream().map(IastRuntime.Finding::source).toList();
        expect(findings.stream().allMatch(f->"PATH_TRAVERSAL".equals(f.ruleId())),"path class for every read: "+findings.stream().map(IastRuntime.Finding::ruleId).toList());
        expect(sources.equals(java.util.List.of("parameter:name","header:X-Name","parameter:list","parameter:m","header:X-Multi","query:querystring","cookie:sid")),"one finding per read, with the name asked for: "+sources);
        for(var f:findings)expect(!(f.method()+f.sink()+f.stack()+f.source()).contains("tainted-"),"a finding must not contain the input value");
        findings.clear();
        decoded();bytes();base64();chars();split();names();safeTransform();
        var transformed=findings.stream().map(IastRuntime.Finding::source).toList();
        expect(transformed.equals(java.util.List.of("parameter:d","parameter:b","parameter:e","parameter:c","parameter:s","parametername:names","headername:names")),"origin kept through URLDecoder, bytes, Base64, chars, split and names; nothing for a constant: "+transformed);
        IastRuntime.exit(previous);
        findings.clear();
        parameter();header();cookie();
        expect(findings.isEmpty(),"outside a request scope the servlet reads are not sources: "+findings.size());
        IastRuntime.configure(null);
        System.out.println("IAST servlet sources: getParameter, getHeader, getParameterValues, getParameterMap, getHeaders, getQueryString, Cookie.getValue, names, URLDecoder, bytes, Base64, chars, split, constant transform, no value in findings and no scope passed");
    }
}
