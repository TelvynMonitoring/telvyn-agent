package system.monitoring.debugger;

import com.datadog.ddwaf.*;
import com.datadog.ddwaf.exception.TimeoutWafException;
import com.google.gson.*;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded query detection. Callers must select explicitly permitted input first. */
public final class LocalAttackDetection implements AutoCloseable {
    private WafHandle handle;
    private String engine;
    public record Result(String outcome, List<String> rules, String engine_version, long elapsed_us) {}

    public LocalAttackDetection() {}
    public static final class InputLimitException extends IllegalArgumentException {
        public InputLimitException(){super("query input limit");}
    }

    public static Map<String,String> permittedQuery(String rawQuery,Set<String> allowed) {
        if(allowed.isEmpty()||allowed.size()>8||allowed.stream().anyMatch(k->!k.matches("[A-Za-z0-9_.-]{1,64}")))throw new IllegalArgumentException("invalid query allowlist");
        if(rawQuery!=null&&rawQuery.length()>8192)throw new InputLimitException();
        Map<String,String> selected=new LinkedHashMap<>();
        if(rawQuery!=null)for(String pair:rawQuery.split("&")) {
            int separator=pair.indexOf('=');
            String key=URLDecoder.decode(separator<0?pair:pair.substring(0,separator),StandardCharsets.UTF_8);
            if(!allowed.contains(key))continue;
            if(selected.containsKey(key))throw new InputLimitException();
            String value=separator<0?"":URLDecoder.decode(pair.substring(separator+1),StandardCharsets.UTF_8);
            if(value.length()>2048)throw new InputLimitException();
            selected.put(key,value);
        }
        return Map.copyOf(selected);
    }

    public synchronized Result inspectPermittedQuery(Map<String,String> selected) {
        long start=System.nanoTime();Set<String> rules=new LinkedHashSet<>();String engineVersion=engine;
        if(selected.size()>8||selected.values().stream().anyMatch(v->v==null||v.length()>2048))return new Result("limit",List.of(),engine,(System.nanoTime()-start)/1000);
        for(String value:selected.values()) {
            Result result=inspectSearchQuery(true,value);engineVersion=result.engine_version();
            if(!Set.of("match","no_match").contains(result.outcome()))return new Result(result.outcome(),List.of(),engineVersion,(System.nanoTime()-start)/1000);
            rules.addAll(result.rules());
        }
        return new Result(rules.isEmpty()?"no_match":"match",List.copyOf(rules),engineVersion,(System.nanoTime()-start)/1000);
    }

    public Result inspectSearchRequest(boolean enabled,String rawQuery) {
        long start=System.nanoTime();
        if(!enabled)return inspectSearchQuery(false,null);
        if(rawQuery!=null&&rawQuery.length()>8192)return new Result("limit",List.of(),engine,(System.nanoTime()-start)/1000);
        String q=null;boolean seen=false;
        try {
            if(rawQuery!=null)for(String pair:rawQuery.split("&")) {
                int split=pair.indexOf('=');
                if("q".equals(split<0?pair:pair.substring(0,split))) {
                    // Ambiguous repeated input must not be silently reduced to its first value.
                    if(seen)return new Result("limit",List.of(),engine,(System.nanoTime()-start)/1000);
                    seen=true;q=split<0?"":URLDecoder.decode(pair.substring(split+1),StandardCharsets.UTF_8);
                }
            }
        }catch(IllegalArgumentException malformed){return new Result("error",List.of(),engine,(System.nanoTime()-start)/1000);}
        return inspectSearchQuery(true,q);
    }

    private synchronized WafHandle engine() throws Exception {
        if(handle!=null)return handle;
        Waf.initialize(false);
        try(var stream=LocalAttackDetection.class.getResourceAsStream("/security/lab-query-v1.json")) {
            if(stream==null)throw new IllegalStateException("missing lab rules");
            var rules=new Gson().fromJson(new InputStreamReader(stream,StandardCharsets.UTF_8),Map.class);
            var builder=new WafBuilder();
            try {
                var diagnostics=builder.addOrUpdateConfig("lab",rules);
                if(diagnostics.getNumConfigError()!=0||diagnostics.rules.getLoaded().size()!=2)throw new IllegalStateException("invalid lab rules");
                handle=builder.buildWafHandleInstance();engine=Waf.getVersion();return handle;
            }finally{builder.close();}
        }
    }

    public synchronized Result inspectSearchQuery(boolean enabled,String q) {
        long start=System.nanoTime();String outcome;List<String> rules=new ArrayList<>();
        if(!enabled)return new Result("disabled",List.of(),engine,(System.nanoTime()-start)/1000);
        if(q!=null&&q.length()>2048)return new Result("limit",List.of(),engine,(System.nanoTime()-start)/1000);
        try(var context=new WafContext(engine())) {
            var result=context.run(Map.of("server.request.query",Map.of("q",q==null?"":q)),new Waf.Limits(8,32,2048,10000,10000),new WafMetrics());
            outcome=result.result==Waf.Result.MATCH?"match":result.result==Waf.Result.OK?"no_match":"error";
            if(result.result==Waf.Result.MATCH) {
                // Native match data contains input values. Only copy known rule IDs out of it.
                for(var event:JsonParser.parseString(result.data).getAsJsonArray()) {
                    String id=event.getAsJsonObject().getAsJsonObject("rule").get("id").getAsString();
                    if(Set.of("telvyn-lab-sqli-v1","telvyn-lab-xss-v1").contains(id)&&!rules.contains(id))rules.add(id);
                }
                if(rules.isEmpty())outcome="error";
            }
        }catch(TimeoutWafException timeout){outcome="timeout";rules.clear();}
        catch(Exception|LinkageError failure){outcome="error";rules.clear();}
        return new Result(outcome,List.copyOf(rules),engine,(System.nanoTime()-start)/1000);
    }

    @Override public synchronized void close(){if(handle!=null){handle.close();handle=null;}}
}
