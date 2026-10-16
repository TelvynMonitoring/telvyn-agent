package system.monitoring.debugger;
import java.lang.reflect.*;
import java.util.function.*;

/** Uses Reactor's supported Micrometer context bridge, never a global request context. */
public final class ReactorIast {
 private static boolean installed;
 private ReactorIast(){}
 public static synchronized void install(ClassLoader loader)throws ReflectiveOperationException {
  if(installed)return;
  var registry=Class.forName("io.micrometer.context.ContextRegistry",true,loader);Object instance=registry.getMethod("getInstance").invoke(null);
  var register=registry.getMethod("registerThreadLocalAccessor",String.class,Supplier.class,Consumer.class,Runnable.class);
  register.invoke(instance,"telvyn.iast.context",(Supplier<Object>)IastRuntime::capture,(Consumer<Object>)IastRuntime::restore,(Runnable)()->IastRuntime.restore(null));
  register.invoke(instance,"telvyn.spring.method",(Supplier<Object>)SpringMvcSecurity::selection,(Consumer<Object>)SpringMvcSecurity::selection,(Runnable)()->SpringMvcSecurity.selection(null));
  Class.forName("reactor.core.publisher.Hooks",true,loader).getMethod("enableAutomaticContextPropagation").invoke(null);installed=true;
 }
 public static Object scoped(Object publisher,Object state){return context(publisher,"telvyn.iast.context",state);}
 public static Object dispatch(Object publisher,Object method){return context(publisher,"telvyn.spring.method",method);}
 public static Object publisher(Object publisher,Object state){
  try{
   Object scoped=context(publisher,"telvyn.iast.context",state);
   return api(scoped).getMethod("doFinally",Consumer.class).invoke(scoped,(Consumer<Object>)signal->IastRuntime.release(state));
  }catch(ReflectiveOperationException failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("reactive lifecycle unavailable");IastRuntime.release(state);return publisher;}
 }
 private static Class<?> api(Object publisher)throws ClassNotFoundException{
  var loader=publisher.getClass().getClassLoader();var mono=Class.forName("reactor.core.publisher.Mono",false,loader);return mono.isInstance(publisher)?mono:Class.forName("reactor.core.publisher.Flux",false,loader);
 }
 private static Object context(Object publisher,String key,Object value){
  try{return api(publisher).getMethod("contextWrite",Function.class).invoke(publisher,(Function<Object,Object>)ctx->{try{return Class.forName("reactor.util.context.Context",false,ctx.getClass().getClassLoader()).getMethod("put",Object.class,Object.class).invoke(ctx,key,value);}catch(ReflectiveOperationException failure){throw new IllegalStateException("reactive context unavailable");}});}
  catch(ReflectiveOperationException failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("reactive context unavailable");return publisher;}
 }
}
