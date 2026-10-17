package system.monitoring.debugger;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.concurrent.atomic.AtomicBoolean;

/** Reports only explicitly supported, non-secret settings; never enumerates the environment. */
final class SdkConfigurationReporter {
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    static final String[] FLAGS = {"enabled", "alloc.enabled", "lock.enabled", "wall.enabled", "exceptions.enabled", "retention.enabled", "wall.events.enabled", "classload.enabled"};
    static JsonObject configuration(String suffix, java.util.function.Function<String,String> property, java.util.function.Function<String,String> environment) {
        String name="telvyn.profiling."+suffix;
        String value=property.apply(name), source="system_property";
        if(value==null||value.isBlank()){value=environment.apply("TELVYN_PROFILING_"+suffix.toUpperCase(java.util.Locale.ROOT).replace('.','_'));source="environment";}
        boolean numeric="period.ms".equals(suffix)||"flush.sec".equals(suffix)||"lock.threshold.ms".equals(suffix);
        if(value==null||value.isBlank()){value=numeric?("flush.sec".equals(suffix)?"15":"10"):"false";source="default";}
        if(numeric){
            // Keep the configured input, before each profiler's limits. Never send invalid raw text.
            try {value=Long.toString(Long.parseLong(value.trim()));} catch(NumberFormatException invalid){value="invalid";}
        }else value=Boolean.toString("true".equalsIgnoreCase(value));
        // Opção alterada pela tela (configuração remota) vence a local e é reportada como "remote".
        String remoteKey=switch(suffix){case "enabled"->"enabled";case "alloc.enabled"->"alloc";case "lock.enabled"->"lock";case "wall.enabled"->"wall";case "exceptions.enabled"->"exceptions";default->null;};
        Boolean remote=remoteKey==null?null:RemoteConfig.profiling(remoteKey);
        if(remote!=null){value=remote.toString();source="remote";}
        JsonObject result=new JsonObject();result.addProperty("name",name);result.addProperty("value",value);result.addProperty("source",source);return result;
    }
    static void start() {
        if(!STARTED.compareAndSet(false,true))return;
        Thread thread=new Thread(()->{
            boolean firstReport=true;
            while(!Thread.currentThread().isInterrupted()) {
                try {
                    JsonObject report=new JsonObject();report.addProperty("service",SnapshotSink.service());report.addProperty("host",SnapshotSink.host());
                    report.addProperty("environment",ProbeMetricSink.environment());report.addProperty("service_version",ProbeMetricSink.version());
                    report.addProperty("sdk_name","telvyn-javaagent");report.addProperty("sdk_version",SdkConfigurationReporter.class.getPackage().getImplementationVersion());
                    report.addProperty("runtime",System.getProperty("java.runtime.version"));
                    JsonArray settings=new JsonArray();for(String flag:FLAGS)settings.add(configuration(flag,System::getProperty,System::getenv));
                    settings.add(configuration("period.ms",System::getProperty,System::getenv));settings.add(configuration("flush.sec",System::getProperty,System::getenv));settings.add(configuration("lock.threshold.ms",System::getProperty,System::getenv));report.add("configurations",settings);
                    // Preserve immediate SDK reporting; allow lifecycle registration before sensor reports.
                    if(!firstReport){settings.add(sensor("attack",SecuritySensorState.attack()));settings.add(sensor("iast",SecuritySensorState.iast()));}
                    if(RemoteConfig.revision()>0){var applied=new JsonObject();applied.addProperty("name","telvyn.remote_config.revision");applied.addProperty("value",Long.toString(RemoteConfig.revision()));applied.addProperty("source","remote");settings.add(applied);}
                    firstReport=false;
                    String url=SnapshotSink.configUrl().replace("/debug/config","/sdk/configuration");
                    CollectorHttp.post(url,report.toString(),10000);
                }catch(Exception ignored){ /* Telemetry must not interrupt the application. */ }
                try{Thread.sleep(60000);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            }
        },"telvyn-sdk-configuration");thread.setDaemon(true);thread.start();
    }
    static JsonObject sensor(String kind,String state){var result=new JsonObject();result.addProperty("name","telvyn.security."+kind+".state");result.addProperty("value",state);result.addProperty("source","runtime");return result;}
}
