package org.apache.commons.lang;

/** Stand-in for commons-lang (not on the diagnostic classpath): same name and signature, the agent only sees the call. */
public class StringEscapeUtils {
    public static String escapeHtml(String text) { return text == null ? null : text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"); }
}
