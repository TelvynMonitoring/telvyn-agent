package system.monitoring.debugger;
import java.lang.instrument.Instrumentation;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/** Functional request context belongs to the exchange until the response body terminates. */
public final class FunctionalWebFluxSecurity{
 private static final String KEY="telvyn.iast.functional";
 public record Invocation(SpringMvcSecurity.ReactiveScope route,Object previous,Object state,Object exchange){}
 private FunctionalWebFluxSecurity(){}
 public static void install(Instrumentation instrumentation){
  var listener=new AgentBuilder.Listener.Adapter(){@Override public void onError(String name,ClassLoader loader,net.bytebuddy.utility.JavaModule module,boolean loaded,Throwable error){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("functional transformation unavailable");}};
  new AgentBuilder.Default().disableClassFormatChanges().with(listener).type(named("org.springframework.web.reactive.function.server.support.HandlerFunctionAdapter"))
   .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Dispatch.class).on(named("handle").and(takesArguments(2))))).installOn(instrumentation);
  new AgentBuilder.Default(new net.bytebuddy.ByteBuddy().ignore(none())).disableClassFormatChanges().with(listener).type(named("org.springframework.web.reactive.function.server.RouterFunctions$RouterFunctionWebHandler"))
   .transform((builder,type,loader,module,domain)->builder
    .visit(Advice.to(DirectDispatch.class).on(takesArguments(2).and(takesArgument(0,named("org.springframework.web.reactive.function.server.HandlerFunction"))).and(takesArgument(1,named("org.springframework.web.reactive.function.server.ServerRequest")))))
    .visit(Advice.to(DirectWrite.class).on(takesArguments(2).and(takesArgument(0,named("org.springframework.web.reactive.function.server.ServerResponse"))).and(takesArgument(1,named("org.springframework.web.server.ServerWebExchange")))))).installOn(instrumentation);
  if(!Boolean.getBoolean("telvyn.iast.enabled"))return;
  new AgentBuilder.Default().disableClassFormatChanges().with(listener).type(named("org.springframework.web.reactive.function.server.ServerRequest"))
   .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Parameter.class).on(named("queryParam").and(takesArguments(String.class))))).installOn(instrumentation);
  new AgentBuilder.Default().disableClassFormatChanges().with(listener).type(named("org.springframework.web.reactive.function.server.DefaultServerRequest"))
   .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Parameters.class).on(named("queryParams").and(takesArguments(0))))).installOn(instrumentation);
  new AgentBuilder.Default().disableClassFormatChanges().with(listener).type(named("org.springframework.web.reactive.function.server.support.ServerResponseResultHandler"))
   .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Write.class).on(named("handleResult").and(takesArguments(2))))).installOn(instrumentation);
 }
 @SuppressWarnings("unchecked") private static Map<String,Object> attributes(Object exchange)throws ReflectiveOperationException{return (Map<String,Object>)Class.forName("org.springframework.web.server.ServerWebExchange",false,exchange.getClass().getClassLoader()).getMethod("getAttributes").invoke(exchange);}
 public static Invocation enter(Object exchange){
  var route=SpringMvcSecurity.reactive(exchange,null);Object previous=IastRuntime.capture(),state=route.allowed()&&Boolean.getBoolean("telvyn.iast.enabled")?IastRuntime.beginFunctional():null;
  try{if(state!=null)attributes(exchange).put(KEY,state);IastRuntime.restore(state);return new Invocation(route,previous,state,exchange);}
  catch(ReflectiveOperationException failure){IastRuntime.release(state);IastRuntime.restore(previous);SpringMvcSecurity.close(route.previous());SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("functional exchange unavailable");return null;}
 }
 private static void discard(Invocation scope){try{attributes(scope.exchange()).remove(KEY,scope.state());}catch(ReflectiveOperationException unavailable){LocalAttackReporter.reportLoss("functional cleanup unavailable");}finally{IastRuntime.release(scope.state());}}
 public static Object returned(Object result,Invocation scope,Throwable error){
  if(scope==null)return result;
  try{
   if(scope.state()==null)return result;
   if(error!=null||result==null){discard(scope);return result;}
   var mono=Class.forName("reactor.core.publisher.Mono",false,result.getClass().getClassLoader());var produced=new AtomicBoolean();
   Object publisher=ReactorIast.scoped(result,scope.state());
   publisher=mono.getMethod("doOnNext",Consumer.class).invoke(publisher,(Consumer<Object>)value->produced.set(true));
   return mono.getMethod("doFinally",Consumer.class).invoke(publisher,(Consumer<Object>)signal->{if(!produced.get()||!(signal instanceof Enum<?> type&&type.name().equals("ON_COMPLETE")))discard(scope);});
  }catch(ReflectiveOperationException failure){discard(scope);SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("functional lifecycle unavailable");return result;}
  finally{IastRuntime.restore(scope.previous());SpringMvcSecurity.close(scope.route().previous());}
 }
 public static Object writing(Object exchange){try{return attributes(exchange).remove(KEY);}catch(ReflectiveOperationException failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("functional write unavailable");return null;}}
 public static class Dispatch{
  @Advice.OnMethodEnter(suppress=Throwable.class) public static Invocation enter(@Advice.Argument(0)Object exchange){return FunctionalWebFluxSecurity.enter(exchange);}
  @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Invocation scope,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result,@Advice.Thrown Throwable error){result=returned(result,scope,error);}
 }
 public static class Parameter{
  @Advice.OnMethodExit(suppress=Throwable.class) public static void exit(@Advice.Argument(0)String name,@Advice.Return Object result){IastRuntime.functionalParameter(name,result);}
 }
 public static Invocation direct(Object request){
  try{return enter(Class.forName("org.springframework.web.reactive.function.server.ServerRequest",false,request.getClass().getClassLoader()).getMethod("exchange").invoke(request));}
  catch(ReflectiveOperationException failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("direct functional exchange unavailable");return null;}
 }
 public static class DirectDispatch{
  @Advice.OnMethodEnter(suppress=Throwable.class) public static Invocation enter(@Advice.Argument(1)Object request){return direct(request);}
  @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Invocation scope,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result,@Advice.Thrown Throwable error){result=returned(result,scope,error);}
 }
 public static class DirectWrite{
  @Advice.OnMethodEnter(suppress=Throwable.class) public static Object enter(@Advice.Argument(1)Object exchange){return writing(exchange);}
  @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Object state,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result,@Advice.Thrown Throwable error){if(state!=null){if(error!=null||result==null)IastRuntime.release(state);else result=ReactorIast.publisher(result,state);}}
 }
 public static class Parameters{
  @Advice.OnMethodExit(suppress=Throwable.class) public static void exit(@Advice.Return Object result){IastRuntime.functionalParameters(result);}
 }
 public static class Write{
  @Advice.OnMethodEnter(suppress=Throwable.class) public static Object enter(@Advice.Argument(0)Object exchange){return writing(exchange);}
  @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Object state,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result,@Advice.Thrown Throwable error){if(state!=null){if(error!=null||result==null)IastRuntime.release(state);else result=ReactorIast.publisher(result,state);}}
 }
}
