package system.monitoring.debugger.profiler;

import java.util.LinkedHashMap;
import java.util.HashSet;

/** Low-cardinality endpoint identity captured before trace export/sampling. */
public final class ProfileEndpointContext {
    private record Span(String parent, String endpoint) {}
    private static final LinkedHashMap<String,Span> SPANS = new LinkedHashMap<>();

    /** OpenTelemetry API type: the application's own, or the copy the OpenTelemetry Java agent relocates. */
    static Class<?> api(String suffix, ClassLoader loader) throws ClassNotFoundException {
        try { return Class.forName("io.opentelemetry." + suffix, false, loader); }
        catch (ClassNotFoundException absent) { return Class.forName("io.opentelemetry.javaagent.shaded.io.opentelemetry." + suffix, false, loader); }
    }

    public static void observe(Object span) {
        if (span == null) return;
        try {
            var loader=span.getClass().getClassLoader();
            var readable=Class.forName("io.opentelemetry.sdk.trace.ReadableSpan",false,loader);
            if(!readable.isInstance(span))return;
            var contextType=api("api.trace.SpanContext",loader);
            var context=readable.getMethod("getSpanContext").invoke(span);
            String trace=(String)contextType.getMethod("getTraceId").invoke(context);
            String id=(String)contextType.getMethod("getSpanId").invoke(context);
            var parent=readable.getMethod("getParentSpanContext").invoke(span);
            String parentId=(String)contextType.getMethod("getSpanId").invoke(parent);
            String endpoint=null;
            if("SERVER".equals(String.valueOf(readable.getMethod("getKind").invoke(span)))) {
                parentId=null; // An unknown local server route must not inherit another server's endpoint.
                var keyType=api("api.common.AttributeKey",loader);
                var stringKey=keyType.getMethod("stringKey",String.class);
                var get=readable.getMethod("getAttribute",keyType);
                String route=(String)get.invoke(span,stringKey.invoke(null,"http.route"));
                String method=(String)get.invoke(span,stringKey.invoke(null,"http.request.method"));
                if(method==null)method=(String)get.invoke(span,stringKey.invoke(null,"http.method"));
                // Never fall back to raw URLs, which may carry identifiers or secrets.
                if(route!=null&&method!=null&&!route.isBlank()&&method.matches("[A-Z]{1,20}"))endpoint=method+" "+route;
                if(endpoint!=null&&(endpoint.length()>1024||endpoint.chars().anyMatch(Character::isISOControl)))endpoint=null;
            }
            synchronized(SPANS) {
                SPANS.put(trace+":"+id,new Span(parentId,endpoint));
                while(SPANS.size()>32768)SPANS.remove(SPANS.keySet().iterator().next());
            }
        } catch(ReflectiveOperationException|RuntimeException ignored) { /* Unsupported SDK stays unattributed. */ }
    }

    static String resolve(String trace,String id) {
        synchronized(SPANS) {
            var visited=new HashSet<String>();
            while(id!=null&&visited.add(id)&&visited.size()<=128) {
                var span=SPANS.get(trace+":"+id);if(span==null)return null;
                if(span.endpoint()!=null)return span.endpoint();
                id=span.parent();
            }
            return null;
        }
    }
}
