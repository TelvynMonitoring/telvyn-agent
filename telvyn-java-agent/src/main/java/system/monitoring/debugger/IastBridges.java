package system.monitoring.debugger;

import java.io.PrintWriter;
import java.util.Locale;
import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import org.xml.sax.InputSource;

/**
 * Sinks whose dangerous argument is not on top of the stack: the call site in application code is replaced by one of these
 * methods, which inspects the argument and then makes the original call (same receiver, same arguments, same result and
 * exceptions). The last two parameters are where the call is: method and line. Names match the replaced methods.
 */
public final class IastBridges {
    private IastBridges() {}
    // XSS: what the application writes to the writer of the HTTP response.
    public static void print(PrintWriter w,String s,String m,int l){IastRuntime.xss(w,s,m,l,"java.io.PrintWriter.print");w.print(s);}
    public static void print(PrintWriter w,Object o,String m,int l){IastRuntime.xss(w,o,m,l,"java.io.PrintWriter.print");w.print(o);}
    public static void print(PrintWriter w,char[] c,String m,int l){IastRuntime.xss(w,c,m,l,"java.io.PrintWriter.print");w.print(c);}
    public static void println(PrintWriter w,String s,String m,int l){IastRuntime.xss(w,s,m,l,"java.io.PrintWriter.println");w.println(s);}
    public static void println(PrintWriter w,Object o,String m,int l){IastRuntime.xss(w,o,m,l,"java.io.PrintWriter.println");w.println(o);}
    public static void println(PrintWriter w,char[] c,String m,int l){IastRuntime.xss(w,c,m,l,"java.io.PrintWriter.println");w.println(c);}
    public static void write(PrintWriter w,String s,String m,int l){IastRuntime.xss(w,s,m,l,"java.io.PrintWriter.write");w.write(s);}
    public static void write(PrintWriter w,char[] c,String m,int l){IastRuntime.xss(w,c,m,l,"java.io.PrintWriter.write");w.write(c);}
    public static void write(PrintWriter w,String s,int off,int len,String m,int l){IastRuntime.xss(w,s,m,l,"java.io.PrintWriter.write");w.write(s,off,len);}
    public static void write(PrintWriter w,char[] c,int off,int len,String m,int l){IastRuntime.xss(w,c,m,l,"java.io.PrintWriter.write");w.write(c,off,len);}
    public static PrintWriter format(PrintWriter w,String f,Object[] a,String m,int l){IastRuntime.xss(w,new Object[]{f,a},m,l,"java.io.PrintWriter.format");return w.format(f,a);}
    public static PrintWriter format(PrintWriter w,Locale x,String f,Object[] a,String m,int l){IastRuntime.xss(w,new Object[]{f,a},m,l,"java.io.PrintWriter.format");return w.format(x,f,a);}
    public static PrintWriter printf(PrintWriter w,String f,Object[] a,String m,int l){IastRuntime.xss(w,new Object[]{f,a},m,l,"java.io.PrintWriter.printf");return w.printf(f,a);}
    public static PrintWriter printf(PrintWriter w,Locale x,String f,Object[] a,String m,int l){IastRuntime.xss(w,new Object[]{f,a},m,l,"java.io.PrintWriter.printf");return w.printf(x,f,a);}
    public static PrintWriter append(PrintWriter w,CharSequence s,String m,int l){IastRuntime.xss(w,s,m,l,"java.io.PrintWriter.append");return w.append(s);}
    public static PrintWriter append(PrintWriter w,CharSequence s,int start,int end,String m,int l){IastRuntime.xss(w,s,m,l,"java.io.PrintWriter.append");return w.append(s,start,end);}

    // LDAP: the search filter (the base name and the filter arguments are not where an injection takes effect).
    public static NamingEnumeration<SearchResult> search(DirContext c,String base,String filter,SearchControls s,String m,int l)throws NamingException{IastRuntime.ldap(filter,m,l,"javax.naming.directory.DirContext.search");return c.search(base,filter,s);}
    public static NamingEnumeration<SearchResult> search(DirContext c,Name base,String filter,SearchControls s,String m,int l)throws NamingException{IastRuntime.ldap(filter,m,l,"javax.naming.directory.DirContext.search");return c.search(base,filter,s);}
    public static NamingEnumeration<SearchResult> search(DirContext c,String base,String filter,Object[] a,SearchControls s,String m,int l)throws NamingException{IastRuntime.ldap(filter,m,l,"javax.naming.directory.DirContext.search");return c.search(base,filter,a,s);}
    public static NamingEnumeration<SearchResult> search(DirContext c,Name base,String filter,Object[] a,SearchControls s,String m,int l)throws NamingException{IastRuntime.ldap(filter,m,l,"javax.naming.directory.DirContext.search");return c.search(base,filter,a,s);}

    // XPath: the expression.
    public static XPathExpression compile(XPath x,String e,String m,int l)throws XPathExpressionException{IastRuntime.xpath(e,m,l,"javax.xml.xpath.XPath.compile");return x.compile(e);}
    public static Object evaluate(XPath x,String e,Object item,QName t,String m,int l)throws XPathExpressionException{IastRuntime.xpath(e,m,l,"javax.xml.xpath.XPath.evaluate");return x.evaluate(e,item,t);}
    public static String evaluate(XPath x,String e,Object item,String m,int l)throws XPathExpressionException{IastRuntime.xpath(e,m,l,"javax.xml.xpath.XPath.evaluate");return x.evaluate(e,item);}
    public static Object evaluate(XPath x,String e,InputSource in,QName t,String m,int l)throws XPathExpressionException{IastRuntime.xpath(e,m,l,"javax.xml.xpath.XPath.evaluate");return x.evaluate(e,in,t);}
    public static String evaluate(XPath x,String e,InputSource in,String m,int l)throws XPathExpressionException{IastRuntime.xpath(e,m,l,"javax.xml.xpath.XPath.evaluate");return x.evaluate(e,in);}
}
