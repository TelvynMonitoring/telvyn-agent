package system.monitoring.debugger;
import java.util.concurrent.*;
import java.util.function.*;

/** Explicit task capture; state is restored per invocation and released at request termination. */
public final class IastAsync {
 private IastAsync(){}
 public record Cleanup(Object context) implements Runnable{public void run(){IastRuntime.release(context);}}
 public record CleanupError(Object context) implements Consumer<Throwable>{public void accept(Throwable error){IastRuntime.release(context);}}
 public static Runnable completion(Runnable callback,Runnable previous){
  if(!(callback instanceof Cleanup cleanup)||previous==null)return callback;
  return ()->{Object prior=IastRuntime.capture();IastRuntime.restore(cleanup.context());try{previous.run();}finally{cleanup.run();IastRuntime.restore(prior);}};
 }
 public static Consumer<Throwable> completionError(Consumer<Throwable> callback,Consumer<Throwable> previous){
  if(!(callback instanceof CleanupError cleanup)||previous==null)return callback;
  return error->{Object prior=IastRuntime.capture();IastRuntime.restore(cleanup.context());try{previous.accept(error);}finally{cleanup.accept(error);IastRuntime.restore(prior);}};
 }
 public record CapturedCallable(Callable<?> task,Object context) implements Callable<Object>{
  public Object call()throws Exception{Object previous=IastRuntime.capture();IastRuntime.restore(context);try{return task.call();}finally{IastRuntime.restore(previous);}}
 }
 public static Object callable(Object task,Object context){
  if(context==null)return task;
  return new CapturedCallable((Callable<?>)task,context);
 }
 public static Callable<?> taskCallable(Callable<?> task){java.util.Objects.requireNonNull(task);return (Callable<?>)callable(task,IastRuntime.capture());}
 public static Runnable taskRunnable(Runnable task){java.util.Objects.requireNonNull(task);Object context=IastRuntime.capture();return context==null?task:()->with(context,()->{task.run();return null;});}
 public static Object webAsyncInterceptor(Object task,Object interceptor){
  try{
   Object callable=task.getClass().getMethod("getCallable").invoke(task);if(!(callable instanceof CapturedCallable captured))return interceptor;
   Class<?> api=Class.forName("org.springframework.web.context.request.async.CallableProcessingInterceptor",false,task.getClass().getClassLoader());
   return java.lang.reflect.Proxy.newProxyInstance(api.getClassLoader(),new Class<?>[]{api},(proxy,method,args)->{
    Object previous=IastRuntime.capture();IastRuntime.restore(captured.context());
    try{return method.invoke(interceptor,args);}catch(java.lang.reflect.InvocationTargetException failure){throw failure.getCause();}
    finally{if(java.util.Set.of("afterCompletion","handleTimeout","handleError").contains(method.getName()))IastRuntime.release(captured.context());IastRuntime.restore(previous);}
   });
  }catch(ReflectiveOperationException failure){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("WebAsyncTask lifecycle unavailable");return interceptor;}
 }
 public static <T> CompletableFuture<T> supplyAsync(Supplier<T> action){return supplyAsync(action,ForkJoinPool.commonPool());}
 public static <T> CompletableFuture<T> supplyAsync(Supplier<T> action,Executor executor){java.util.Objects.requireNonNull(action);Object context=IastRuntime.capture();if(context==null)return CompletableFuture.supplyAsync(action,executor);return CompletableFuture.supplyAsync(()->with(context,action),executor);}
 public static CompletableFuture<Void> runAsync(Runnable action){return runAsync(action,ForkJoinPool.commonPool());}
 public static CompletableFuture<Void> runAsync(Runnable action,Executor executor){java.util.Objects.requireNonNull(action);Object context=IastRuntime.capture();if(context==null)return CompletableFuture.runAsync(action,executor);return CompletableFuture.runAsync(()->with(context,()->{action.run();return null;}),executor);}
 public static <T,R> CompletableFuture<R> thenApplyAsync(CompletableFuture<T> future,Function<T,R> action){return thenApplyAsync(future,action,ForkJoinPool.commonPool());}
 public static <T,R> CompletableFuture<R> thenApplyAsync(CompletableFuture<T> future,Function<T,R> action,Executor executor){java.util.Objects.requireNonNull(action);Object context=IastRuntime.capture();if(context==null)return future.thenApplyAsync(action,executor);return future.thenApplyAsync(value->with(context,()->action.apply(value)),executor);}
 private static <T>T with(Object context,Supplier<T> action){Object previous=IastRuntime.capture();IastRuntime.restore(context);try{return action.get();}finally{IastRuntime.restore(previous);}}
 public static Object returned(Object result,Object context,Throwable error){
  if(context==null)return result;
  if(error!=null){IastRuntime.release(context);return result;}
  if(result!=null&&result.getClass().getName().equals("org.springframework.web.context.request.async.WebAsyncTask"))return result;
  if(result instanceof Callable<?>){Object wrapped=callable(result,context);return (Callable<Object>)()->{try{return ((Callable<?>)wrapped).call();}finally{IastRuntime.release(context);}};}
  if(result instanceof CompletionStage<?> future){future.whenComplete((value,failure)->IastRuntime.release(context));return result;}
  if(result!=null&&result.getClass().getName().startsWith("reactor.core.publisher."))return ReactorIast.publisher(result,context);
  if(result!=null&&result.getClass().getName().equals("org.springframework.web.context.request.async.DeferredResult"))try{
   Runnable cleanup=new Cleanup(context);
   result.getClass().getMethod("onCompletion",Runnable.class).invoke(result,cleanup);
   result.getClass().getMethod("onTimeout",Runnable.class).invoke(result,cleanup);
   result.getClass().getMethod("onError",Consumer.class).invoke(result,new CleanupError(context));return result;
  }catch(ReflectiveOperationException failure){LocalAttackReporter.reportLoss("async lifecycle unavailable");}
  IastRuntime.release(context);return result;
 }
}
