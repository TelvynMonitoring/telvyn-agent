package system.monitoring.debugger;
import com.google.gson.Gson;
import java.util.*;
/** Bounded interval aggregates independent of snapshot throttling. Never blocks the application. */
final class ProbeMetricSink {
 static final double[] BOUNDS={1,5,10,50,100,500,1000,5000};
 record Key(String name,String action){}
 static final class Values {long count;double sum;double last;long lastTime;final long[] buckets=new long[BOUNDS.length+1];void add(double duration){count++;sum+=duration;last=duration;lastTime=System.currentTimeMillis();int bucket=0;while(bucket<BOUNDS.length&&duration>BOUNDS[bucket])bucket++;buckets[bucket]++;}void merge(Values other){if(count==0){last=other.last;lastTime=other.lastTime;}count+=other.count;sum+=other.sum;for(int i=0;i<buckets.length;i++)buckets[i]+=other.buckets[i];}}
 private static final Map<Key,Values> VALUES=new LinkedHashMap<>();
 private static long start=System.currentTimeMillis();private static boolean started;
 private static final String ENV=identity("telvyn.env","TELVYN_ENV","deployment.environment.name","deployment.environment");
 private static final String VERSION=identity("telvyn.version","TELVYN_VERSION","service.version");
 static String environment(){return ENV;}static String version(){return VERSION;}
 static synchronized void observe(String name,String action,double duration){
  var key=new Key(name,action);if(!VALUES.containsKey(key)&&VALUES.size()>=400)return;
  VALUES.computeIfAbsent(key,ignored->new Values()).add(duration);
  if(!started){started=true;var thread=new Thread(ProbeMetricSink::loop,"telvyn-debugger-metrics");thread.setDaemon(true);thread.start();}
 }
 private static void loop(){while(true){try{Thread.sleep(10000);flush();}catch(InterruptedException stopped){Thread.currentThread().interrupt();return;}catch(Exception ignored){}}}
 private static void flush()throws Exception{
  Map<Key,Values> batch;long begin,end=System.currentTimeMillis();synchronized(ProbeMetricSink.class){if(VALUES.isEmpty())return;batch=new LinkedHashMap<>(VALUES);VALUES.clear();begin=start;start=end;}
  boolean accepted=false;
  try{String url=SnapshotSink.configUrl().replaceFirst("/debug/config$","/metrics");accepted=CollectorHttp.post(url,payload(batch,begin,end),10000).status()/100==2;}
  finally{if(!accepted)synchronized(ProbeMetricSink.class){start=Math.min(start,begin);batch.forEach((key,value)->{if(VALUES.containsKey(key)||VALUES.size()<400)VALUES.computeIfAbsent(key,ignored->new Values()).merge(value);});}}
 }
 static String payload(Map<Key,Values> batch,long begin,long end){
  var metrics=new ArrayList<Map<String,Object>>();for(var entry:batch.entrySet()){
   var point=new LinkedHashMap<String,Object>();point.put("startTimeUnixNano",Long.toString(begin*1000000));point.put("timeUnixNano",Long.toString(end*1000000));var value=entry.getValue();var metric=new LinkedHashMap<String,Object>();metric.put("name",entry.getKey().name());
   if(entry.getKey().action().equals("gauge")){point.remove("startTimeUnixNano");point.put("timeUnixNano",Long.toString(value.lastTime*1000000));point.put("asDouble",value.last);metric.put("unit","1");metric.put("gauge",Map.of("dataPoints",List.of(point)));}
   else if(entry.getKey().action().equals("count")){point.put("asInt",Long.toString(value.count));metric.put("unit","1");metric.put("sum",Map.of("aggregationTemporality",1,"isMonotonic",true,"dataPoints",List.of(point)));}
   else{point.put("count",Long.toString(value.count));point.put("sum",value.sum);point.put("explicitBounds",BOUNDS);point.put("bucketCounts",Arrays.stream(value.buckets).mapToObj(Long::toString).toList());metric.put("unit","ms");metric.put("histogram",Map.of("aggregationTemporality",1,"dataPoints",List.of(point)));}metrics.add(metric);
  }
  var attrs=new ArrayList<Map<String,Object>>();attribute(attrs,"service.name",SnapshotSink.service());attribute(attrs,"deployment.environment.name",ENV);attribute(attrs,"service.version",VERSION);attribute(attrs,"host.name",SnapshotSink.host());
  return new Gson().toJson(Map.of("resourceMetrics",List.of(Map.of("resource",Map.of("attributes",attrs),"scopeMetrics",List.of(Map.of("scope",Map.of("name","telvyn.debugger"),"metrics",metrics))))));
 }
 private static void attribute(List<Map<String,Object>> attrs,String key,String value){if(value!=null)attrs.add(Map.of("key",key,"value",Map.of("stringValue",value)));}
 private static String identity(String property,String env,String... attrs){String value=System.getProperty(property);if(value==null)value=System.getenv(env);if(value!=null)return value;String resource=System.getProperty("otel.resource.attributes",System.getenv("OTEL_RESOURCE_ATTRIBUTES"));if(resource!=null)for(String key:attrs)for(String pair:resource.split(",")){int at=pair.indexOf('=');if(at>0&&pair.substring(0,at).trim().equals(key))return pair.substring(at+1).trim();}return null;}
}
