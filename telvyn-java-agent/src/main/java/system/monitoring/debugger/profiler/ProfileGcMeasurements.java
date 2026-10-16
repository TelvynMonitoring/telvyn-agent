package system.monitoring.debugger.profiler;

import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;
import jdk.jfr.consumer.RecordingFile;
import jdk.jfr.consumer.RecordingStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Read completed pause events between recorded boundaries, not asynchronous delivery times. */
final class ProfileGcMeasurements {
    @Name("telvyn.ProfileWindowBoundary") @StackTrace(false)
    static class Boundary extends Event {long id;}
    private record Pause(Instant start,Instant end,long nanos) {}
    private record Heap(Instant time,long gcId,boolean after,long used,long committed) {}
    private record OldCycle(Instant start,Instant end,long gcId) {}
    private static final AtomicLong sequence=new AtomicLong();
    private static volatile RecordingStream stream;

    static void attach(RecordingStream recording,int flushSeconds) {
        var available=jdk.jfr.FlightRecorder.getFlightRecorder().getEventTypes().stream().map(type->type.getName()).collect(java.util.stream.Collectors.toSet());
        if(!available.containsAll(java.util.Set.of("jdk.GCPhasePause","jdk.GCHeapSummary","jdk.OldGarbageCollection")))return;
        recording.enable(Boundary.class).withoutStackTrace();
        recording.enable("jdk.GCPhasePause").withoutThreshold().withoutStackTrace();
        recording.enable("jdk.GCHeapSummary").withoutStackTrace();
        recording.enable("jdk.OldGarbageCollection").withoutThreshold().withoutStackTrace();
        recording.enable("jdk.DataLoss").withoutStackTrace();
        recording.setMaxAge(Duration.ofSeconds(Math.max(60L,flushSeconds*3L)));
        recording.setMaxSize(32L*1024*1024);
        stream=recording;
    }
    static long mark() {
        if(stream==null)return 0;
        var boundary=new Boundary();if(!boundary.isEnabled())return 0;
        boundary.id=sequence.incrementAndGet();boundary.commit();return boundary.id;
    }
    static synchronized Map<String,Object> between(long from,long to) {
        if(from==0||to<=from||stream==null)return Map.of();
        Path snapshot=null;
        try {
            // A live stream can deliver older events in later batches; snapshot before calculating.
            snapshot=Files.createTempFile("telvyn-profile-gc-",".jfr");
            stream.dump(snapshot);
            if(Files.size(snapshot)>64L*1024*1024)return Map.of();
            return read(snapshot,from,to);
        } catch(Exception|LinkageError unavailable) {return Map.of();}
        finally {if(snapshot!=null)try{Files.deleteIfExists(snapshot);}catch(Exception ignored){}}
    }
    static Map<String,Object> read(Path snapshot,long from,long to)throws java.io.IOException {
        Instant start=null,end=null;var pauses=new ArrayList<Pause>();var heaps=new ArrayList<Heap>();var oldCycles=new ArrayList<OldCycle>();
        try(var recording=new RecordingFile(snapshot)) {
            while(recording.hasMoreEvents()) {
                var event=recording.readEvent();String name=event.getEventType().getName();
                if(name.equals("telvyn.ProfileWindowBoundary")) {
                    if(event.getLong("id")==from)start=event.getStartTime();
                    if(event.getLong("id")==to)end=event.getStartTime();
                } else if(name.equals("jdk.GCPhasePause")) {
                    if(pauses.size()>=10000)return Map.of();
                    pauses.add(new Pause(event.getStartTime(),event.getEndTime(),event.getDuration().toNanos()));
                } else if(name.equals("jdk.GCHeapSummary")) {
                    if(heaps.size()>=20000)return Map.of();
                    String when=event.getString("when");
                    if(!when.equals("Before GC")&&!when.equals("After GC"))return Map.of();
                    var space=(jdk.jfr.consumer.RecordedObject)event.getValue("heapSpace");
                    heaps.add(new Heap(event.getStartTime(),event.getLong("gcId"),when.equals("After GC"),event.getLong("heapUsed"),space.getLong("committedSize")));
                } else if(name.equals("jdk.OldGarbageCollection")) {
                    if(oldCycles.size()>=10000)return Map.of();
                    oldCycles.add(new OldCycle(event.getStartTime(),event.getEndTime(),event.getLong("gcId")));
                } else if(name.equals("jdk.DataLoss"))return Map.of();
            }
        }
        if(start==null||end==null||!end.isAfter(start))return Map.of();
        long count=0,total=0,max=0,window=Duration.between(start,end).toNanos();
        for(var pause:pauses)if(pause.end().isAfter(start)&&!pause.end().isAfter(end)) {
            if(pause.start().isBefore(start)||pause.nanos()<0)return Map.of();
            count++;total=Math.addExact(total,pause.nanos());max=Math.max(max,pause.nanos());
        }
        if(total>window)return Map.of();
        var result=new LinkedHashMap<String,Object>();
        result.put("gc_source","jfr_gc_phase_pause");result.put("gc_window_ns",window);
        result.put("gc_pause_count",count);result.put("gc_pause_total_ns",total);
        if(count>0)result.put("gc_pause_max_ns",max);
        long heapCount=0,committedTotal=0,committedMax=0,afterCount=0,afterTotal=0,afterMax=0,oldMax=-1;
        var completedOld=new java.util.HashSet<Long>();var measuredOld=new java.util.HashSet<Long>();boolean oldCovered=true;
        for(var cycle:oldCycles)if(cycle.end().isAfter(start)&&!cycle.end().isAfter(end)) {
            if(cycle.start().isBefore(start))oldCovered=false;
            completedOld.add(cycle.gcId());
        }
        for(var heap:heaps)if(heap.time().isAfter(start)&&!heap.time().isAfter(end)) {
            if(heap.used()<0||heap.committed()<heap.used())return Map.of();
            heapCount++;committedTotal=Math.addExact(committedTotal,heap.committed());committedMax=Math.max(committedMax,heap.committed());
            if(heap.after()) {
                afterCount++;afterTotal=Math.addExact(afterTotal,heap.used());afterMax=Math.max(afterMax,heap.used());
                if(completedOld.contains(heap.gcId())){oldMax=Math.max(oldMax,heap.used());measuredOld.add(heap.gcId());}
            }
        }
        if(heapCount>0){result.put("gc_heap_count",heapCount);result.put("gc_heap_committed_total_bytes",committedTotal);result.put("gc_heap_committed_max_bytes",committedMax);}
        if(afterCount>0){result.put("gc_heap_after_count",afterCount);result.put("gc_heap_after_total_bytes",afterTotal);result.put("gc_heap_after_max_bytes",afterMax);}
        if(oldCovered){result.put("gc_old_count",(long)completedOld.size());if(oldMax>=0&&measuredOld.containsAll(completedOld))result.put("gc_old_heap_max_bytes",oldMax);}
        return result;
    }
}
