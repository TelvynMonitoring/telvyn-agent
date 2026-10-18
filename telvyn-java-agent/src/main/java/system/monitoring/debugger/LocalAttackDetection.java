package system.monitoring.debugger;

import com.google.gson.*;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded query detection. Callers must select explicitly permitted input first. */
public final class LocalAttackDetection implements AutoCloseable {
    /** Motor do WAF (no class loader isolado, ver WafEngines). */
    private Object handle;
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

    @SuppressWarnings("unchecked")
    private synchronized Object engine() throws Throwable {
        if(handle!=null)return handle;
        try(var stream=LocalAttackDetection.class.getResourceAsStream("/security/lab-query-v1.json")) {
            if(stream==null)throw new IllegalStateException("missing lab rules");
            var rules=(Map<String,Object>)new Gson().fromJson(new InputStreamReader(stream,StandardCharsets.UTF_8),Map.class);
            handle=WafEngines.build(rules,"lab",2);engine=WafEngines.version();return handle;
        }
    }

    public synchronized Result inspectSearchQuery(boolean enabled,String q) {
        long start=System.nanoTime();String outcome;List<String> rules=new ArrayList<>();
        if(!enabled)return new Result("disabled",List.of(),engine,(System.nanoTime()-start)/1000);
        if(q!=null&&q.length()>2048)return new Result("limit",List.of(),engine,(System.nanoTime()-start)/1000);
        Object context=null;
        try {
            context=WafEngines.open(engine());
            Object[] result=WafEngines.run(context,Map.of("server.request.query",Map.of("q",q==null?"":q)),new int[]{8,32,2048,10000,10000});
            outcome="match".equals(result[0])?"match":"ok".equals(result[0])?"no_match":"timeout".equals(result[0])?"timeout":"error";
            if("match".equals(result[0])) {
                // Native match data contains input values. Only copy known rule IDs out of it.
                for(var event:JsonParser.parseString((String)result[1]).getAsJsonArray()) {
                    String id=event.getAsJsonObject().getAsJsonObject("rule").get("id").getAsString();
                    if(Set.of("telvyn-lab-sqli-v1","telvyn-lab-xss-v1").contains(id)&&!rules.contains(id))rules.add(id);
                }
                if(rules.isEmpty())outcome="error";
            }
            if("timeout".equals(outcome))rules.clear();
        }catch(Throwable failure){outcome="error";rules.clear();}
        finally{if(context!=null)try{WafEngines.close(context);}catch(Throwable ignored){/* contexto já liberado */}}
        return new Result(outcome,List.copyOf(rules),engine,(System.nanoTime()-start)/1000);
    }

    @Override public synchronized void close(){if(handle!=null){try{WafEngines.close(handle);}catch(Throwable ignored){/* já liberado */}handle=null;}}
}
