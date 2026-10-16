package system.monitoring.debugger;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;

/** Sanitized reports; never accepts request contents. */
public final class LocalAttackReporter implements AutoCloseable {
    private static final java.util.concurrent.atomic.AtomicLong losses=new java.util.concurrent.atomic.AtomicLong(),lastWarning=new java.util.concurrent.atomic.AtomicLong();
    public static void reportLoss(String reason) {
        long total=losses.incrementAndGet(),now=System.nanoTime(),last=lastWarning.get();
        if((last==0||now-last>60_000_000_000L)&&lastWarning.compareAndSet(last,now))System.err.println("Telvyn security data discarded: "+reason+"; total="+total+" (warnings limited to one/minute)");
    }
    private final ArrayBlockingQueue<String> queue=new ArrayBlockingQueue<>(64);
    private final Thread sender;
    private final String service,host,environment,version,rulesVersion;
    public LocalAttackReporter() {
        this(labEndpoint(),SnapshotSink.service(),SnapshotSink.host(),ProbeMetricSink.environment(),ProbeMetricSink.version(),"lab-query-1");
    }
    private static String labEndpoint(){
        if(!"security-lab".equals(ProbeMetricSink.environment()))throw new IllegalStateException("configured security-lab identity required");
        return Collector.url()+"/v1/security/lab";
    }
    public LocalAttackReporter(String endpoint,String service,String host,String environment,String version,String rulesVersion) {
        URI destination=URI.create(endpoint);
        if(destination.getHost()==null||destination.getUserInfo()!=null||destination.getQuery()!=null||destination.getFragment()!=null||!("https".equals(destination.getScheme())||"http".equals(destination.getScheme())))throw new IllegalArgumentException("invalid collector endpoint");
        for(String identity:java.util.Arrays.asList(service,host,environment))if(identity==null||identity.isBlank()||identity.length()>255)throw new IllegalArgumentException("invalid service identity");
        if(version!=null&&version.length()>255)throw new IllegalArgumentException("invalid service version");
        this.service=service;this.host=host;this.environment=environment;this.version=version;this.rulesVersion=rulesVersion;
        sender=new Thread(()->{while(!Thread.currentThread().isInterrupted())try {
            String report=queue.take();
            int status=CollectorHttp.post(endpoint,report,5000).status();
            if(status<200||status>=300)reportLoss("export HTTP "+status);
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();}catch(Exception failed){reportLoss("export failure");}},"telvyn-security-export");
        sender.setDaemon(true);sender.start();
    }
    public boolean report(LocalAttackDetection.Result result,String trace,String span) {
        boolean queued=true;
        var rules=result.rules().isEmpty()?Collections.singletonList((String)null):result.rules();
        for(String rule:rules) {
            var report=new JsonObject();report.addProperty("id",UUID.randomUUID().toString());report.addProperty("service",service);report.addProperty("host",host);report.addProperty("environment",environment);report.addProperty("service_version",version);report.addProperty("outcome",result.outcome());report.addProperty("rule_id",rule);report.addProperty("rules_version",rulesVersion);report.addProperty("engine_version",result.engine_version());report.addProperty("elapsed_us",result.elapsed_us());
            if(trace!=null&&span!=null){report.addProperty("trace_id",trace);report.addProperty("span_id",span);}
            queued&=queue.offer(report.toString());
        }
        if(!queued)reportLoss("report queue full");
        return queued;
    }
    public boolean reportIast(IastRuntime.Finding finding,String trace,String span) {
        var report=new JsonObject();report.addProperty("id",UUID.randomUUID().toString());report.addProperty("service",service);report.addProperty("host",host);report.addProperty("environment",environment);report.addProperty("service_version",version);
        report.addProperty("outcome","match");report.addProperty("rule_id",finding.ruleId()==null?"SQL_INJECTION":finding.ruleId());report.addProperty("rules_version",finding.rulesVersion());report.addProperty("engine_version","telvyn-iast-2");report.addProperty("elapsed_us",finding.elapsedUs());
        report.addProperty("code_method",finding.method());report.addProperty("code_line",finding.line());
        // Context the agent already sees at the sink: the instrumented API, the masked statement, the call stack and the input source.
        if(finding.sink()!=null)report.addProperty("sink",finding.sink());
        if(finding.sql()!=null)report.addProperty("sql",finding.sql());
        if(finding.stack()!=null&&!finding.stack().isEmpty()){var frames=new JsonArray();finding.stack().forEach(frames::add);report.add("stack",frames);}
        if(finding.source()!=null)report.addProperty("source",finding.source());
        String[] request=IastRuntime.request();
        if(request!=null&&request[0]!=null&&request[0].matches("[A-Z]{1,20}"))report.addProperty("request_method",request[0]);
        if(request!=null&&request[1]!=null&&request[1].length()<=1024&&request[1].indexOf('?')<0)report.addProperty("request_path",request[1]);
        if(trace!=null&&span!=null){report.addProperty("trace_id",trace);report.addProperty("span_id",span);}
        boolean accepted=queue.offer(report.toString());if(!accepted)reportLoss("IAST report queue full");return accepted;
    }
    @Override public void close(){sender.interrupt();}
}
