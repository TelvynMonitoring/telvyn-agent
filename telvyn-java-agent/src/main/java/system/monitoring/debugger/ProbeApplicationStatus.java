package system.monitoring.debugger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Configuration receipt is not instrumentation or execution: keep these proofs separate. */
final class ProbeApplicationStatus {
 private static final Map<String,State> STATES=new ConcurrentHashMap<>();
 private static final class State {volatile String status="unmatched";volatile int methods;final AtomicLong calls=new AtomicLong();}
 static void prepare(List<Probe> probes){STATES.clear();if(probes!=null)for(var probe:probes)STATES.put(probe.toString(),new State());}
 static void lineTransformed(String className,String method,int line){var state=STATES.get(className+"#"+method+"@"+line);if(state!=null){state.methods++;state.status="instrumented";}}
 static void transformed(String className,Map<String,Integer> methods){for(var entry:STATES.entrySet())if(entry.getKey().startsWith(className+"#")){String method=entry.getKey().substring(className.length()+1);int count=methods.getOrDefault(method,0);if(count>0){entry.getValue().methods=count;entry.getValue().status="instrumented";}}}
 static void failed(String className){for(var entry:STATES.entrySet())if(entry.getKey().startsWith(className+"#"))entry.getValue().status="error";}
 static void called(String method){int dot=method.lastIndexOf('.');if(dot<1)return;var state=STATES.get(method.substring(0,dot)+"#"+method.substring(dot+1));if(state!=null){state.methods=Math.max(1,state.methods);state.status="instrumented";state.calls.incrementAndGet();}}
 static String json(){StringBuilder out=new StringBuilder("[");boolean first=true;for(var key:new TreeSet<>(STATES.keySet())){var value=STATES.get(key);if(value==null)continue;if(!first)out.append(',');first=false;out.append("{\"target\":\"").append(escape(key)).append("\",\"status\":\"").append(value.status).append("\",\"instrumented_methods\":").append(value.methods).append(",\"observed_calls\":").append(value.calls.get()).append('}');}return out.append(']').toString();}
 static String escape(String text){return text.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r");}
}
