package system.monitoring.debugger.profiler;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.ref.WeakReference;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Opcodes;

/** SourceFile basenames observed at class definition; no source paths or bytecode retained. */
public final class ProfileSourceFiles {
    private record Entry(WeakReference<ClassLoader> loader,boolean bootstrap,String file) {}
    private static final Map<String,Entry> files=new HashMap<>();
    private static boolean installed,ready;
    private static int bytes;
    private ProfileSourceFiles() {}
    private static final class SourceVisitor extends ClassVisitor {
        String file="";
        SourceVisitor(){super(Opcodes.ASM9);}
        @Override public void visitSource(String source,String debug){file=basename(source);}
    }

    public static void install(Instrumentation instrumentation) throws Exception {
        synchronized(ProfileSourceFiles.class){if(installed)return;installed=true;}
        // Resolve the ASM reader before observing class loading, avoiding recursive initialization.
        try(var input=ProfileSourceFiles.class.getResourceAsStream("ProfileSourceFiles.class")) {
            new ClassReader(input).accept(new SourceVisitor(),ClassReader.SKIP_CODE|ClassReader.SKIP_FRAMES);
        }
        record(ProfileSourceFiles.class.getName(),ProfileSourceFiles.class.getClassLoader(),"",false);
        ClassFileTransformer observer=new ClassFileTransformer() {
            @Override public byte[] transform(ClassLoader loader,String name,Class<?> redefined,
                    ProtectionDomain domain,byte[] bytecode) {
                if(name==null)return null;
                try {
                    var source=new SourceVisitor();
                    new ClassReader(bytecode).accept(source,ClassReader.SKIP_CODE|ClassReader.SKIP_FRAMES);
                    record(name.replace('/','.'),loader,source.file,redefined!=null);
                } catch(Throwable ignored) {record(name.replace('/','.'),loader,"",true);}
                return null;
            }
        };
        instrumentation.addTransformer(observer,false);
        // Already loaded definitions are unknown; do not read a possibly different classpath resource.
        for(Class<?> type:instrumentation.getAllLoadedClasses())record(type.getName(),type.getClassLoader(),"",false);
        synchronized(ProfileSourceFiles.class){ready=true;}
    }

    private static synchronized void record(String name,ClassLoader loader,String file,boolean redefined) {
        Entry previous=files.get(name);
        if(previous!=null) {
            boolean same=previous.bootstrap()?loader==null:loader!=null&&previous.loader().get()==loader;
            // JFR/folded names do not identify our loader object. Collisions/redefinitions stay unknown.
            if(!same||redefined)files.put(name,new Entry(new WeakReference<>(null),false,""));
            return;
        }
        int size=name.length()+file.length()+64;
        if(files.size()<16384&&bytes+size<=2*1024*1024) {
            files.put(name,new Entry(new WeakReference<>(loader),loader==null,redefined?"":file));bytes+=size;
        }
    }

    static synchronized String file(String className) {
        Entry entry=ready?files.get(className):null;
        return entry==null?"":entry.file();
    }

    private static String basename(String value) {
        if(value==null||value.isBlank()||value.length()>255||value.equals(".")||value.equals("..")
                ||value.indexOf('/')>=0||value.indexOf('\\')>=0||value.indexOf(';')>=0||value.indexOf(':')>=0
                ||value.chars().anyMatch(Character::isISOControl))return "";
        return value;
    }
}
