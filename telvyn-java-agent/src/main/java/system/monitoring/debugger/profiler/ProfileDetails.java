package system.monitoring.debugger.profiler;

import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedThread;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/** Bounded event reservoir; aggregate weights remain separate from sampled timeline events. */
final class ProfileDetails {
    record Event(long time_ms,long duration_ns,long thread_id,String thread,String kind,long weight,String method,int line,String signature,String allocated_type,List<String> stack,boolean stack_truncated,List<Integer> stack_lines,Long object_age_ns,Long allocation_time_ms,String retained_type) {}
    record Group(String trace_id,String span_id,String allocated_type,String folded,String endpoint) {}
    record GroupKey(String trace,String span,String allocated) {}
    record LineKey(String folded,List<Integer> lines,List<String> files) {}
    record LineStack(String folded,List<Integer> lines,List<String> files,long weight) {}
    record Window(long observed_events,List<Event> events,Map<String,Long> allocated_types,List<Group> stack_groups,List<LineStack> line_stacks,Map<String,Object> window_metrics) {
        Window(long observed,List<Event> events,Map<String,Long> allocations,List<Group> groups,List<LineStack> origins){this(observed,events,allocations,groups,origins,Map.of());}
        Window(long observed,List<Event> events,Map<String,Long> allocations,List<Group> groups){this(observed,events,allocations,groups,List.of());}
    }
    private final List<Event> events=new ArrayList<>();
    private final Map<String,Long> allocations=new LinkedHashMap<>();
    private final Map<GroupKey,JfrCpuProfiler.FoldAccumulator> groups=new LinkedHashMap<>();
    private int groupStacks;
    private long seen;
    private final Map<LineKey,Long> lineStacks=new LinkedHashMap<>();
    private int lineBytes;
    private final ProfileWindowMeasurements measurements=new ProfileWindowMeasurements();
    synchronized long beginWindow(){return measurements.begin();}
    synchronized void add(RecordedEvent event,RecordedThread thread,long weight,String folded,ProfilerTraceContext.Link link) {
        boolean retention=event.getEventType().getName().equals("jdk.OldObjectSample");
        if((thread==null&&!retention)||weight<=0)return;
        var stack=event.getStackTrace();
        // Aggregate recorded JFR line variants before reservoir sampling. Wall keeps its old contract.
        if(stack!=null&&!stack.isTruncated()) {
            var recordedLines=new ArrayList<Integer>();
            var recordedFiles=new ArrayList<String>();
            for(var item:stack.getFrames())if(item.isJavaFrame()&&item.getMethod()!=null){
                recordedLines.add(Math.max(-1,item.getLineNumber()));
                recordedFiles.add(ProfileSourceFiles.file(item.getMethod().getType().getName()));
            }
            Collections.reverse(recordedLines);
            Collections.reverse(recordedFiles);
            if(recordedLines.size()<=JfrCpuProfiler.MAX_DEPTH&&recordedLines.size()==folded.split(";",-1).length){
                var key=new LineKey(folded,List.copyOf(recordedLines),List.copyOf(recordedFiles));
                int bytes=folded.length()+recordedLines.size()*16+recordedFiles.stream().mapToInt(String::length).sum()+64;
                if(lineStacks.containsKey(key))lineStacks.merge(key,weight,Long::sum);
                else if(lineStacks.size()<4096&&lineBytes+bytes<=200000){lineStacks.put(key,weight);lineBytes+=bytes;}
            }
        }
        var frame=stack==null?null:stack.getFrames().stream().filter(f->f.isJavaFrame()&&f.getMethod()!=null).findFirst().orElse(null);
        var method=frame==null?null:frame.getMethod();
        var frames=new ArrayList<String>();var lines=new ArrayList<Integer>();int stackBytes=0;boolean truncated=false;
        if(stack!=null)for(var item:stack.getFrames()) {
            if(!item.isJavaFrame()||item.getMethod()==null)continue;
            String name=item.getMethod().getType().getName()+"."+item.getMethod().getName();
            if(frames.size()>=128||stackBytes+name.length()>1024){truncated=true;break;}
            frames.add(name);lines.add(item.getLineNumber());stackBytes+=name.length();
        }
        Collections.reverse(frames);
        Collections.reverse(lines);
        String allocated="";
        if(event.hasField("objectClass")) {var type=event.getClass("objectClass");if(type!=null)allocated=type.getName();}
        if(!allocated.isEmpty())allocations.merge(allocations.containsKey(allocated)||allocations.size()<511?allocated:"[other allocated types]",weight,Long::sum);
        var key=new GroupKey(link==null?"":link.traceId(),link==null?"":link.spanId(),allocated);
        if(groupStacks<4096&&(groups.containsKey(key)||groups.size()<128)) {
            var accumulator=groups.computeIfAbsent(key,ignored->new JfrCpuProfiler.FoldAccumulator());
            int before=accumulator.size();accumulator.add(folded,weight);groupStacks+=accumulator.size()-before;
        }
        String kind=event.getEventType().getName();
        // Exception messages can contain secrets; retain only the exception class.
        if(event.hasField("thrownClass")){var thrown=event.getClass("thrownClass");if(thrown!=null)kind=cap(kind+":"+thrown.getName(),1024);}
        String retained=null;
        if(retention){jdk.jfr.consumer.RecordedObject object=event.getValue("object");var type=object==null?null:object.getClass("type");retained=type==null?"":cap(type.getName(),1024);}
        Event item=new Event(event.getStartTime().toEpochMilli(),event.getDuration().toNanos(),thread==null?0:thread.getJavaThreadId(),thread==null?"":cap(thread.getJavaName(),255),kind,weight,
                method==null?"":cap(method.getType().getName()+"."+method.getName(),1024),frame==null?-1:frame.getLineNumber(),method==null?"":cap(method.getDescriptor(),1024),cap(allocated,1024),List.copyOf(frames),truncated,List.copyOf(lines),retention?event.getDuration("objectAge").toNanos():null,retention?event.getInstant("allocationTime").toEpochMilli():null,retained);
        retain(item);
    }
    synchronized void addWall(java.lang.management.ThreadInfo thread,long timestamp,int periodMs) {
        addWall(thread.getThreadId(),thread.getThreadName(),thread.getThreadState(),thread.getStackTrace(),false,timestamp,periodMs);
    }
    synchronized void addWall(long id,String thread,Thread.State state,StackTraceElement[] stack,boolean virtual,long timestamp,int periodMs) {
        var frames=new ArrayList<String>();var lines=new ArrayList<Integer>();int bytes=0;boolean truncated=false;
        for(var frame:stack) {
            String name=frame.getClassName()+"."+frame.getMethodName();
            if(frames.size()>=128||bytes+name.length()>1024){truncated=true;break;}
            frames.add(name);lines.add(Math.max(-1,frame.getLineNumber()));bytes+=name.length();
        }
        if(frames.isEmpty())return;
        String method=frames.get(0);int line=lines.get(0);
        Collections.reverse(frames);Collections.reverse(lines);
        retain(new Event(timestamp,periodMs*1_000_000L,id,cap(thread,255),"wall."+(virtual?"virtual.":"")+state.name(),1,method,line,"","",List.copyOf(frames),truncated,List.copyOf(lines),null,null,null));
    }
    private void retain(Event item) {
        long index=ThreadLocalRandom.current().nextLong(++seen);
        // Bound stack-bearing records below the ingest payload limit.
        if(events.size()<512)events.add(item);else if(index<512)events.set((int)index,item);
    }
    synchronized Window drain(){
        var stacks=new ArrayList<Group>();int bytes=0;
        for(var entry:groups.entrySet()){String folded=entry.getValue().drain();bytes+=folded.length();if(bytes>JfrCpuProfiler.MAX_FOLDED_BYTES)break;var key=entry.getKey();stacks.add(new Group(key.trace(),key.span(),key.allocated(),folded,ProfileEndpointContext.resolve(key.trace(),key.span())));}
        var origins=lineStacks.entrySet().stream().map(entry->new LineStack(entry.getKey().folded(),entry.getKey().lines(),entry.getKey().files(),entry.getValue())).toList();
        var result=new Window(seen,List.copyOf(events),Map.copyOf(allocations),stacks,origins,measurements.drain());
        events.clear();allocations.clear();groups.clear();lineStacks.clear();lineBytes=0;groupStacks=0;seen=0;return result;
    }
    private static String cap(String value,int max){return value==null?"":value.substring(0,Math.min(max,value.length()));}
}
