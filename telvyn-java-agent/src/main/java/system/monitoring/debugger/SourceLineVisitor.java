package system.monitoring.debugger;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.jar.asm.*;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.visitor.StackAwareMethodVisitor;
import java.util.*;

/** Genuine LineNumberTable hook. Local slots are read only while their LVT ranges are active. */
final class SourceLineVisitor {
 private static final java.lang.reflect.Field STACK=stackField();
 private static java.lang.reflect.Field stackField(){try{var field=StackAwareMethodVisitor.class.getDeclaredField("current");field.setAccessible(true);return field;}catch(Exception unavailable){return null;}}
 private static boolean emptyStack(StackAwareMethodVisitor visitor){try{return STACK!=null&&((List<?>)STACK.get(visitor)).isEmpty();}catch(Exception unavailable){return false;}}
 record Variable(String name,String descriptor,int slot,Label start,Label end){}
 record Site(int line,int position,List<Variable> variables,boolean localsAvailable){}
 static final class Metadata {
  final Map<String,List<Site>> methods=new HashMap<>();
  Metadata(byte[] bytes){new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9){
   @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
    var labels=new IdentityHashMap<Label,Integer>();var lines=new ArrayList<int[]>();var variables=new ArrayList<Variable>();
    return new MethodVisitor(Opcodes.ASM9){int position;
     @Override public void visitLabel(Label label){labels.put(label,position++);}
     @Override public void visitLineNumber(int line,Label label){lines.add(new int[]{line,labels.getOrDefault(label,-1)});}
     @Override public void visitLocalVariable(String name,String desc,String signature,Label start,Label end,int index){variables.add(new Variable(name,desc,index,start,end));}
     @Override public void visitEnd(){var sites=new ArrayList<Site>();for(var line:lines){var active=variables.stream().filter(v->labels.getOrDefault(v.start(),Integer.MAX_VALUE)<=line[1]&&line[1]<labels.getOrDefault(v.end(),Integer.MIN_VALUE)).sorted(Comparator.comparingInt(Variable::slot)).limit(10).toList();sites.add(new Site(line[0],line[1],active,!variables.isEmpty()));}methods.put(name+descriptor,sites);}
    };
   }
  },ClassReader.SKIP_FRAMES);}
 }
 static AsmVisitorWrapper wrapper(String className,ClassLoader loader,List<Probe> probes){
  byte[] bytes;
  try(var stream=loader==null?ClassLoader.getSystemResourceAsStream(className.replace('.','/')+".class"):loader.getResourceAsStream(className.replace('.','/')+".class")){if(stream==null)throw new IllegalArgumentException("class bytecode unavailable");bytes=stream.readNBytes(4*1024*1024+1);if(bytes.length>4*1024*1024)throw new IllegalArgumentException("class bytecode too large");}
  catch(Exception failure){throw new IllegalArgumentException("source metadata unavailable",failure);}
  var metadata=new Metadata(bytes);
  return new AsmVisitorWrapper.ForDeclaredMethods().writerFlags(ClassWriter.COMPUTE_FRAMES|ClassWriter.COMPUTE_MAXS).method(ElementMatchers.isMethod(),(type,method,visitor,context,pool,writerFlags,readerFlags)->new StackAwareMethodVisitor(visitor,method){
   int occurrence;final List<Site> sites=metadata.methods.getOrDefault(method.getInternalName()+method.getDescriptor(),List.of());
   final Map<Label,Integer> actualLabels=new IdentityHashMap<>();final List<Variable> actualVariables=new ArrayList<>();final List<Site> loadedSites=new ArrayList<>();int actualPosition;
   @Override public void visitLabel(Label label){actualLabels.put(label,actualPosition++);super.visitLabel(label);}
   @Override public void visitLocalVariable(String name,String descriptor,String signature,Label start,Label end,int slot){actualVariables.add(new Variable(name,descriptor,slot,start,end));super.visitLocalVariable(name,descriptor,signature,start,end,slot);}
   @Override public void visitEnd(){
    for(var site:loadedSites){var active=actualVariables.stream().filter(v->actualLabels.getOrDefault(v.start(),Integer.MAX_VALUE)<=site.position()&&site.position()<actualLabels.getOrDefault(v.end(),Integer.MIN_VALUE)).sorted(Comparator.comparingInt(Variable::slot)).limit(10).map(v->v.name()+":"+v.descriptor()+":"+v.slot()).toList();var expected=site.variables().stream().map(v->v.name()+":"+v.descriptor()+":"+v.slot()).toList();if(!active.equals(expected))throw new IllegalStateException("Local-variable metadata differs from actual class bytecode; refusing line capture");}
    super.visitEnd();
   }
   @Override public void visitLineNumber(int line,Label label){
    super.visitLineNumber(line,label);Site site=occurrence<sites.size()?sites.get(occurrence):null;occurrence++;
    // A catch handler clears the operand stack. Never inject at a non-empty-stack source site.
    // If the pinned ByteBuddy stack inspection is unavailable, leave the target unmatched.
    if(!emptyStack(this))return;
    for(var probe:probes)if(probe.line==line&&probe.methodName.equals(method.getInternalName())){
     // Refuse guessed metadata if a prior transformer changed line ordering.
     boolean available=site!=null&&site.line()==line&&site.localsAvailable();var vars=available?site.variables():List.<Variable>of();
     if(available)loadedSites.add(new Site(line,actualLabels.getOrDefault(label,-1),vars,true));
     var begin=new Label();var end=new Label();var failed=new Label();var resume=new Label();super.visitTryCatchBlock(begin,end,failed,"java/lang/Throwable");super.visitLabel(begin);
     super.visitLdcInsn(className+"."+method.getInternalName());integer(line);integer(vars.size());super.visitTypeInsn(Opcodes.ANEWARRAY,"java/lang/String");
     for(int i=0;i<vars.size();i++){super.visitInsn(Opcodes.DUP);integer(i);super.visitLdcInsn(vars.get(i).name());super.visitInsn(Opcodes.AASTORE);}
     integer(vars.size());super.visitTypeInsn(Opcodes.ANEWARRAY,"java/lang/Object");
     for(int i=0;i<vars.size();i++){super.visitInsn(Opcodes.DUP);integer(i);load(vars.get(i));super.visitInsn(Opcodes.AASTORE);}
     super.visitInsn(available?Opcodes.ICONST_1:Opcodes.ICONST_0);
     super.visitMethodInsn(Opcodes.INVOKESTATIC,"system/monitoring/debugger/SnapshotSink","onLine","(Ljava/lang/String;I[Ljava/lang/String;[Ljava/lang/Object;Z)V",false);
     super.visitLabel(end);super.visitJumpInsn(Opcodes.GOTO,resume);super.visitLabel(failed);super.visitInsn(Opcodes.POP);super.visitLabel(resume);
     ProbeApplicationStatus.lineTransformed(className,probe.methodName,line);
    }
   }
   void integer(int number){super.visitLdcInsn(number);}
   void load(Variable variable){var t=Type.getType(variable.descriptor());switch(t.getSort()){
    case Type.BOOLEAN,Type.BYTE,Type.CHAR,Type.SHORT,Type.INT -> {super.visitVarInsn(Opcodes.ILOAD,variable.slot());box(switch(t.getSort()){case Type.BOOLEAN->"Boolean";case Type.BYTE->"Byte";case Type.CHAR->"Character";case Type.SHORT->"Short";default->"Integer";},t.getDescriptor());}
    case Type.LONG->{super.visitVarInsn(Opcodes.LLOAD,variable.slot());box("Long","J");}
    case Type.FLOAT->{super.visitVarInsn(Opcodes.FLOAD,variable.slot());box("Float","F");}
    case Type.DOUBLE->{super.visitVarInsn(Opcodes.DLOAD,variable.slot());box("Double","D");}
    default->{if(variable.descriptor().equals("Ljava/lang/String;"))super.visitVarInsn(Opcodes.ALOAD,variable.slot());else super.visitLdcInsn("[non-primitive local omitted]");}
   }}
   void box(String type,String descriptor){super.visitMethodInsn(Opcodes.INVOKESTATIC,"java/lang/"+type,"valueOf","("+descriptor+")Ljava/lang/"+type+";",false);}
  });
 }
}
