package system.monitoring.debugger;
import com.google.gson.*;
import java.util.*;
/** No application method calls: conditions inspect only boxed primitives and elapsed time. */
final class ProbePolicies {
 record Condition(String source,String operator,Integer arg_index,Double number,Boolean bool){}
 record Policy(String action,String metric_name,Condition condition,String value_source,Integer value_arg_index){Policy(String action,String metric_name,Condition condition){this(action,metric_name,condition,null,null);}}
 record Rule(String target,Policy policy){}
 private static volatile Map<String,List<Policy>> policies=Map.of();
 static List<Rule> parse(JsonElement json){
  if(json==null||!json.isJsonArray()||json.getAsJsonArray().size()>200)throw new IllegalArgumentException("Invalid probe policies");
  var rules=new ArrayList<Rule>();var gson=new Gson();
  for(var entry:json.getAsJsonArray()){
   var rule=gson.fromJson(entry,Rule.class);validate(rule);rules.add(rule);
  }return List.copyOf(rules);
 }
 static void validate(Rule rule){
  if(rule==null||rule.target()==null||rule.target().length()>512||!rule.target().contains("#")||rule.policy()==null)throw new IllegalArgumentException();
  var p=rule.policy();if(p.action()==null||!Set.of("snapshot","count","duration","gauge").contains(p.action()))throw new IllegalArgumentException();
  if(p.action().equals("gauge")){if(p.value_source()==null||!Set.of("arg","returned").contains(p.value_source())||p.value_source().equals("arg")&&(p.value_arg_index()==null||p.value_arg_index()<0||p.value_arg_index()>255)||p.value_source().equals("returned")&&p.value_arg_index()!=null)throw new IllegalArgumentException();}
  else if(p.value_source()!=null||p.value_arg_index()!=null)throw new IllegalArgumentException();
  if(rule.target().contains("@")&&(!Set.of("snapshot","count").contains(p.action())||p.condition()!=null))throw new IllegalArgumentException();
  if(!p.action().equals("snapshot")&&(p.metric_name()==null||!p.metric_name().matches("debug\\.[a-z][a-z0-9_.]{0,100}")))throw new IllegalArgumentException();
  var c=p.condition();if(c==null)return;
  if(c.source()==null||!Set.of("duration_ms","exception","arg").contains(c.source())||c.operator()==null||!Set.of("gt","gte","lt","lte","eq","ne").contains(c.operator()))throw new IllegalArgumentException();
  if(c.source().equals("exception")){if(!Set.of("eq","ne").contains(c.operator())||c.bool()==null||c.number()!=null||c.arg_index()!=null)throw new IllegalArgumentException();}
  else if(c.number()==null||!Double.isFinite(c.number())||c.bool()!=null||c.source().equals("arg")&&(c.arg_index()==null||c.arg_index()<0||c.arg_index()>255)||c.source().equals("duration_ms")&&c.arg_index()!=null)throw new IllegalArgumentException();
 }
 static void update(List<Rule> rules){var grouped=new HashMap<String,List<Policy>>();for(var rule:rules){validate(rule);grouped.computeIfAbsent(rule.target(),key->new ArrayList<>()).add(rule.policy());}var next=new HashMap<String,List<Policy>>();grouped.forEach((key,value)->next.put(key,List.copyOf(value)));policies=Map.copyOf(next);}
 static boolean observe(String method,Object[] args,Object returned,Throwable error,long nanos){
  int dot=method.lastIndexOf('.');var selected=dot<0?null:policies.get(method.substring(0,dot)+"#"+method.substring(dot+1));
  if(selected==null)return true;boolean snapshot=false;
  for(var policy:selected)if(matches(policy.condition(),args,error,nanos)){
   if(policy.action().equals("snapshot"))snapshot=true;
   else if(policy.action().equals("gauge")){Object value=policy.value_source().equals("returned")?(error==null?returned:null):args!=null&&policy.value_arg_index()<args.length?args[policy.value_arg_index()]:null;Double numeric=primitive(value);if(numeric!=null)ProbeMetricSink.observe(policy.metric_name(),"gauge",numeric);}
   else ProbeMetricSink.observe(policy.metric_name(),policy.action(),Math.max(0,nanos)/1_000_000.0);
  }return snapshot;
 }
 private static Double primitive(Object value){if(!(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long||value instanceof Float||value instanceof Double))return null;double number=((Number)value).doubleValue();return Double.isFinite(number)?number:null;}
 static boolean matches(Condition c,Object[] args,Throwable error,long nanos){
  if(c==null)return true;
  if(c.source().equals("exception")){boolean equal=(error!=null)==c.bool();return c.operator().equals("eq")?equal:!equal;}
  double actual;
  if(c.source().equals("duration_ms"))actual=Math.max(0,nanos)/1_000_000.0;
  else {if(args==null||c.arg_index()>=args.length)return false;Object value=args[c.arg_index()];if(!(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long||value instanceof Float||value instanceof Double))return false;actual=((Number)value).doubleValue();}
  if(!Double.isFinite(actual))return false;double threshold=c.number();return switch(c.operator()){case "gt"->actual>threshold;case "gte"->actual>=threshold;case "lt"->actual<threshold;case "lte"->actual<=threshold;case "eq"->actual==threshold;case "ne"->actual!=threshold;default->false;};
 }
}
