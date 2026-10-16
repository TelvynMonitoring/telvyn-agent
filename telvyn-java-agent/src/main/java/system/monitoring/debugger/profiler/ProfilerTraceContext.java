package system.monitoring.debugger.profiler;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;
import java.lang.instrument.Instrumentation;
import java.time.Instant;
import java.util.*;

/** Captures context on the application thread, never on the JFR consumer thread. */
public final class ProfilerTraceContext {
    public record Link(String traceId, String spanId, long threadId, long startNano, long endNano,
                       Instant start, Instant end) {}
    private record Binding(long thread, Link previous, Link current) {}
    private static final Map<Object, Binding> SCOPES = new IdentityHashMap<>();
    private static final Map<Long, Link> ACTIVE = new HashMap<>();
    private static final Deque<Link> CLOSED = new ArrayDeque<>();
    private static final Map<Long, Deque<Link>> CLOSED_BY_THREAD = new HashMap<>();
    private static final int LIMIT = 8192;
    private static boolean installed;
    private static final java.lang.reflect.Method THREAD_ID = threadIdMethod();
    private static java.lang.reflect.Method threadIdMethod() {
        try {return Thread.class.getMethod("threadId");}
        catch(NoSuchMethodException unavailable) {return null;}
    }
    public static long threadId(Thread thread) {
        if(THREAD_ID==null)return thread.getId();
        try {return (long)THREAD_ID.invoke(thread);}
        catch(ReflectiveOperationException failure) {throw new IllegalStateException("thread identity unavailable",failure);}
    }

    public static synchronized void install(Instrumentation instrumentation) {
        if (installed) return;
        new AgentBuilder.Default().disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .type(ElementMatchers.hasSuperType(ElementMatchers.named("io.opentelemetry.context.ContextStorage"))
                .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(AttachAdvice.class)
                .on(ElementMatchers.named("attach").and(ElementMatchers.takesArguments(1)))))
            .type(ElementMatchers.hasSuperType(ElementMatchers.named("io.opentelemetry.context.Scope"))
                .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CloseAdvice.class)
                .on(ElementMatchers.named("close").and(ElementMatchers.takesArguments(0)))))
            .type(ElementMatchers.named("io.opentelemetry.sdk.trace.SdkSpan"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(EndAdvice.class)
                .on(ElementMatchers.named("end"))))
            .installOn(instrumentation);
        installed = true;
    }

    public static synchronized void attached(Object context, Object scope) {
        if (scope == null) return;
        long thread = threadId(Thread.currentThread());
        if (SCOPES.size() >= LIMIT) { finish(ACTIVE.remove(thread)); return; }
        Link previous = ACTIVE.get(thread);
        Link current = extract(context, thread);
        // No-op scopes may be shared singletons; never bind an unchanged context to them.
        if (same(previous, current)) return;
        if (SCOPES.containsKey(scope)) { finish(ACTIVE.remove(thread)); return; }
        finish(previous);
        SCOPES.put(scope, new Binding(thread, previous, current));
        if (current == null) ACTIVE.remove(thread); else ACTIVE.put(thread, current);
    }

    public static synchronized void closed(Object scope) {
        Binding binding = SCOPES.get(scope);
        if (binding == null || binding.thread != threadId(Thread.currentThread())) return;
        SCOPES.remove(scope);
        finish(ACTIVE.remove(binding.thread));
        Link previous = binding.previous;
        if (previous != null) ACTIVE.put(binding.thread, new Link(previous.traceId, previous.spanId,
            binding.thread, System.nanoTime(), 0, Instant.now(), null));
    }

    private static boolean same(Link first, Link second) {
        return first == null ? second == null : second != null && first.traceId.equals(second.traceId) && first.spanId.equals(second.spanId);
    }
    private static void finish(Link link) {
        if (link == null) return;
        Link finished = new Link(link.traceId, link.spanId, link.threadId, link.startNano, System.nanoTime(), link.start, Instant.now());
        CLOSED.addLast(finished);
        CLOSED_BY_THREAD.computeIfAbsent(link.threadId, ignored -> new ArrayDeque<>()).addLast(finished);
        while (CLOSED.size() > LIMIT) {
            Link expired = CLOSED.removeFirst();
            Deque<Link> history = CLOSED_BY_THREAD.get(expired.threadId);
            history.removeFirst();
            if (history.isEmpty()) CLOSED_BY_THREAD.remove(expired.threadId);
        }
    }
    public static synchronized Link at(long thread, Instant sampledAt) {
        Link current = ACTIVE.get(thread);
        if (current != null && !sampledAt.isBefore(current.start)) return current;
        Deque<Link> history = CLOSED_BY_THREAD.get(thread);
        if (history == null) return null;
        var iterator = history.descendingIterator();
        while (iterator.hasNext()) {
            Link link = iterator.next();
            if (link.threadId == thread && !sampledAt.isBefore(link.start) && sampledAt.isBefore(link.end)) return link;
        }
        return null;
    }
    private static Link extract(Object context, long thread) {
        if (context == null) return null;
        try {
            ClassLoader loader = context.getClass().getClassLoader();
            Class<?> span = Class.forName("io.opentelemetry.api.trace.Span", false, loader);
            Class<?> contextType = Class.forName("io.opentelemetry.context.Context", false, loader);
            Object value = span.getMethod("fromContext", contextType).invoke(null, context);
            ProfileEndpointContext.observe(value);
            Object spanContext = span.getMethod("getSpanContext").invoke(value);
            Class<?> spanContextType = Class.forName("io.opentelemetry.api.trace.SpanContext", false, loader);
            String trace = (String)spanContextType.getMethod("getTraceId").invoke(spanContext);
            String id = (String)spanContextType.getMethod("getSpanId").invoke(spanContext);
            if (!trace.matches("[0-9a-f]{32}") || trace.equals("0".repeat(32)) || !id.matches("[0-9a-f]{16}") || id.equals("0".repeat(16))) return null;
            return new Link(trace, id, thread, System.nanoTime(), 0, Instant.now(), null);
        } catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }
    public static class AttachAdvice {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.Argument(0) Object context, @Advice.Return Object scope) { ProfilerTraceContext.attached(context, scope); }
    }
    public static class EndAdvice {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This Object span) { ProfileEndpointContext.observe(span); }
    }
    public static class CloseAdvice {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object scope) { ProfilerTraceContext.closed(scope); }
    }
}
