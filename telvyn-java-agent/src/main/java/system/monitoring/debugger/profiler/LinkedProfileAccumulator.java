package system.monitoring.debugger.profiler;

import java.util.*;

/** Aggregate totals and bounded attributed subsets; subsets are never added to totals twice. */
final class LinkedProfileAccumulator {
    record LinkStack(String traceId, String spanId, String folded) {}
    record Window(String folded, List<LinkStack> links) {}
    private final JfrCpuProfiler.FoldAccumulator all = new JfrCpuProfiler.FoldAccumulator();
    private final Map<String,JfrCpuProfiler.FoldAccumulator> linked = new LinkedHashMap<>();
    synchronized void add(String stack, ProfilerTraceContext.Link link) {
        add(stack,link,1);
    }
    synchronized void add(String stack, ProfilerTraceContext.Link link, long weight) {
        if (stack == null || stack.isEmpty() || weight <= 0 || all.size() >= 4096) return;
        all.add(stack,weight);
        if (link == null) return;
        String key=link.traceId()+":"+link.spanId();
        if (!linked.containsKey(key) && linked.size() >= 128) return;
        linked.computeIfAbsent(key,k -> new JfrCpuProfiler.FoldAccumulator()).add(stack,weight);
    }
    synchronized Window drain() {
        List<LinkStack> links=new ArrayList<>();
        int bytes=0;
        for (var entry:linked.entrySet()) {
            String folded=entry.getValue().drain();
            bytes+=folded.length();
            if(bytes>JfrCpuProfiler.MAX_FOLDED_BYTES) break;
            var ids=entry.getKey().split(":",2);
            links.add(new LinkStack(ids[0],ids[1],folded));
        }
        linked.clear();
        return new Window(all.drain(),links);
    }
}
