package system.monitoring.securitylab;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import system.monitoring.debugger.IastRuntime;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

/**
 * Focused diagnostic for the Java IAST classes XSS, LDAP, XPath, trust boundary and weak randomness.
 * Run with assertions and the agent in iast-only mode; nothing leaves the process (no LDAP server, no network, no files).
 */
public class IastJvmRulesCheck {
    static String token(String name){return new String("tainted-"+name);}
    static final StringWriter BODY=new StringWriter();
    static final PrintWriter RESPONSE_WRITER=new PrintWriter(BODY);
    static <T> T proxy(Class<T> type,java.lang.reflect.InvocationHandler handler){return type.cast(Proxy.newProxyInstance(IastJvmRulesCheck.class.getClassLoader(),new Class<?>[]{type},handler));}
    static final HttpServletRequest REQUEST=proxy(HttpServletRequest.class,(p,m,a)->m.getName().equals("getParameter")?token((String)a[0]):null);
    static final HttpServletResponse RESPONSE=proxy(HttpServletResponse.class,(p,m,a)->m.getName().equals("getWriter")?RESPONSE_WRITER:null);
    static final HttpSession SESSION=proxy(HttpSession.class,(p,m,a)->null);
    static final DirContext LDAP=proxy(DirContext.class,(p,m,a)->null);

    static void xssPrint()throws Exception{RESPONSE.getWriter().print("<p>"+REQUEST.getParameter("name")+"</p>");}
    static void xssFormat()throws Exception{RESPONSE.getWriter().format(REQUEST.getParameter("fmt"),"x");}
    static void xssChars()throws Exception{RESPONSE.getWriter().write(REQUEST.getParameter("chars").toCharArray());}
    static void xssOtherWriter(){new PrintWriter(new StringWriter()).print(REQUEST.getParameter("log"));}
    static void xssConstant()throws Exception{RESPONSE.getWriter().print("<p>fixed</p>");}
    static void ldap()throws Exception{LDAP.search("ou=users,dc=example,dc=com","(uid="+REQUEST.getParameter("uid")+")",new SearchControls());}
    static void ldapArgs()throws Exception{LDAP.search("ou=users,dc=example,dc=com","(uid={0})",new Object[]{REQUEST.getParameter("uid2")},new SearchControls());}
    static void xpath(){try{javax.xml.xpath.XPathFactory.newInstance().newXPath().compile("/users/user[@name='"+REQUEST.getParameter("user")+"']");}catch(javax.xml.xpath.XPathExpressionException invalid){ /* only the call matters */ }}
    static void xpathConstant(){try{javax.xml.xpath.XPathFactory.newInstance().newXPath().compile("/users/user[@name='fixed']");}catch(javax.xml.xpath.XPathExpressionException invalid){ /* only the call matters */ }}
    static void sessionValue(){SESSION.setAttribute("userid",REQUEST.getParameter("id"));}
    static void sessionName(){SESSION.setAttribute(REQUEST.getParameter("key"),"10340");}
    static void sessionConstant(){SESSION.setAttribute("color","blue");}
    static void weakRandom(){new java.util.Random().nextInt();}
    static void weakMath(){Math.random();}
    static void secureRandom(){new java.security.SecureRandom().nextInt();}
    // Escaping for HTML protects the response, not the session nor any other sink; a builder keeps the origin.
    static void sessionEscaped(){SESSION.setAttribute("userid",org.apache.commons.lang.StringEscapeUtils.escapeHtml(REQUEST.getParameter("esc")));}
    static void xssEscaped()throws Exception{RESPONSE.getWriter().print("<p>"+org.apache.commons.lang.StringEscapeUtils.escapeHtml(REQUEST.getParameter("safe"))+"</p>");}
    static void xssMixed()throws Exception{RESPONSE.getWriter().print(org.apache.commons.lang.StringEscapeUtils.escapeHtml(REQUEST.getParameter("a"))+REQUEST.getParameter("b"));}
    static void builder(){new java.io.File(new StringBuilder(REQUEST.getParameter("sb")).reverse().reverse().toString());}
    // Through java.net.URI (a JDK class loaded before the agent): the URI and its path keep the origin.
    static void uriFile()throws Exception{new java.io.File(new java.net.URI("file",null,"/telvyn-nonexistent/"+REQUEST.getParameter("uri"),null,null));}
    static void uriPath()throws Exception{new java.io.File(new java.net.URI("file:///telvyn-nonexistent/"+REQUEST.getParameter("uri2")).getPath());}
    static void uriConstant()throws Exception{new java.io.File(new java.net.URI("file",null,"/telvyn-nonexistent/fixed",null,null));}
    static void expect(boolean condition,String message){if(!condition)throw new AssertionError(message);}

    public static void main(String[] args)throws Exception{
        var findings=new ArrayList<IastRuntime.Finding>();
        IastRuntime.configure(findings::add);
        Object previous=IastRuntime.openRequest("POST","/lab/*");
        xssPrint();xssFormat();xssChars();xssOtherWriter();xssConstant();
        ldap();ldapArgs();xpath();xpathConstant();
        sessionValue();sessionName();sessionConstant();
        weakRandom();weakMath();secureRandom();
        sessionEscaped();xssEscaped();xssMixed();builder();
        uriFile();uriPath();uriConstant();
        var got=findings.stream().map(f->f.ruleId()+"|"+f.source()).toList();
        expect(got.equals(java.util.List.of("XSS|parameter:name","XSS|parameter:fmt","XSS|parameter:chars","LDAP_INJECTION|parameter:uid","XPATH_INJECTION|parameter:user",
            "TRUST_BOUNDARY_VIOLATION|parameter:id","TRUST_BOUNDARY_VIOLATION|parameter:key","WEAK_RANDOMNESS|null","WEAK_RANDOMNESS|null",
            "TRUST_BOUNDARY_VIOLATION|parameter:esc","XSS|parameter:b","PATH_TRAVERSAL|parameter:sb",
            "PATH_TRAVERSAL|parameter:uri","PATH_TRAVERSAL|parameter:uri2")),
            "one finding per unsafe call; nothing for another writer, constants, LDAP arguments or SecureRandom: "+got);
        expect(findings.stream().filter(f->f.ruleId().equals("WEAK_RANDOMNESS")).allMatch(f->"iast-jvm-flaws-1".equals(f.rulesVersion())),"weak randomness is a flaw without input");
        expect(findings.stream().filter(f->!f.ruleId().equals("WEAK_RANDOMNESS")).allMatch(f->"iast-q-jvm-sinks-1".equals(f.rulesVersion())),"the others start from input");
        for(var f:findings)expect(!(f.method()+f.sink()+f.stack()+f.source()).contains("tainted-"),"a finding must not contain the input value");
        expect(java.util.Arrays.equals(IastRuntime.request(),new String[]{"POST","/lab/*"}),"the request method and route travel with the scope");
        expect(BODY.toString().contains("tainted-name"),"the response still receives what the application wrote");
        IastRuntime.exit(previous);
        findings.clear();
        xssPrint();ldap();sessionValue();weakRandom();
        expect(findings.isEmpty(),"outside a request scope nothing is reported: "+findings.size());
        IastRuntime.configure(null);
        System.out.println("IAST JVM rules: XSS (print, format, chars; other writer and constant quiet), LDAP filter (arguments quiet), XPath (constant quiet), trust boundary (name and value; constant quiet), weak randomness (Random, Math.random; SecureRandom quiet), HTML escaping (session still reported, response quiet, mixed reported), builder, URI (multi-argument constructor and getPath; constant quiet), request route, response preserved, no scope passed");
    }
}
