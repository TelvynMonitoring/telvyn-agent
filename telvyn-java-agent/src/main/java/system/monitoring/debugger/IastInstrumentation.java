package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.*;
import net.bytebuddy.pool.TypePool;
import static net.bytebuddy.matcher.ElementMatchers.*;

public final class IastInstrumentation {
    static final java.util.Set<String> SERVLET_RESPONSES=java.util.Set.of("javax/servlet/ServletResponse","javax/servlet/http/HttpServletResponse","javax/servlet/ServletResponseWrapper","javax/servlet/http/HttpServletResponseWrapper",
        "jakarta/servlet/ServletResponse","jakarta/servlet/http/HttpServletResponse","jakarta/servlet/ServletResponseWrapper","jakarta/servlet/http/HttpServletResponseWrapper");
    // owner.method+descriptor -> receiver type of the bridge in IastBridges (same name and arguments, plus method and line).
    static final java.util.Map<String,String> BRIDGES=bridges();
    private static java.util.Map<String,String> bridges(){
        var map=new java.util.HashMap<String,String>();
        String writer="Ljava/io/PrintWriter;";
        for(String d:new String[]{"print(Ljava/lang/String;)V","print(Ljava/lang/Object;)V","print([C)V","println(Ljava/lang/String;)V","println(Ljava/lang/Object;)V","println([C)V",
                "write(Ljava/lang/String;)V","write([C)V","write(Ljava/lang/String;II)V","write([CII)V",
                "format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/io/PrintWriter;","format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/io/PrintWriter;",
                "printf(Ljava/lang/String;[Ljava/lang/Object;)Ljava/io/PrintWriter;","printf(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/io/PrintWriter;",
                "append(Ljava/lang/CharSequence;)Ljava/io/PrintWriter;","append(Ljava/lang/CharSequence;II)Ljava/io/PrintWriter;"})map.put("java/io/PrintWriter."+d,writer);
        String context="Ljavax/naming/directory/DirContext;";
        for(String owner:new String[]{"javax/naming/directory/DirContext","javax/naming/directory/InitialDirContext"})
            for(String d:new String[]{"search(Ljava/lang/String;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;","search(Ljavax/naming/Name;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;",
                    "search(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;","search(Ljavax/naming/Name;Ljava/lang/String;[Ljava/lang/Object;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration;"})map.put(owner+"."+d,context);
        for(String d:new String[]{"compile(Ljava/lang/String;)Ljavax/xml/xpath/XPathExpression;","evaluate(Ljava/lang/String;Ljava/lang/Object;Ljavax/xml/namespace/QName;)Ljava/lang/Object;","evaluate(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/String;",
                "evaluate(Ljava/lang/String;Lorg/xml/sax/InputSource;Ljavax/xml/namespace/QName;)Ljava/lang/Object;","evaluate(Ljava/lang/String;Lorg/xml/sax/InputSource;)Ljava/lang/String;"})map.put("javax/xml/xpath/XPath."+d,"Ljavax/xml/xpath/XPath;");
        return java.util.Map.copyOf(map);
    }
    // owner.method+descriptor -> where the source is: A receiver only, B receiver with one argument, C the argument of an
    // instance call, D the argument of a static call, E the first of two static arguments.
    // HTML escaping: the result keeps the origin but no longer counts for XSS (it still counts for SQL, commands, the session...).
    static final java.util.Map<String,Character> XSS_SANITIZERS=java.util.Map.of(
        "org/apache/commons/lang/StringEscapeUtils.escapeHtml(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/apache/commons/lang3/StringEscapeUtils.escapeHtml4(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/apache/commons/lang3/StringEscapeUtils.escapeHtml3(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/apache/commons/text/StringEscapeUtils.escapeHtml4(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/springframework/web/util/HtmlUtils.htmlEscape(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/owasp/encoder/Encode.forHtml(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/owasp/encoder/Encode.forHtmlContent(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/owasp/encoder/Encode.forHtmlAttribute(Ljava/lang/String;)Ljava/lang/String;",'D',
        "org/owasp/esapi/Encoder.encodeForHTML(Ljava/lang/String;)Ljava/lang/String;",'C',
        "org/owasp/esapi/Encoder.encodeForHTMLAttribute(Ljava/lang/String;)Ljava/lang/String;",'C');
    // Constructors whose new object keeps the origin of their single argument -> type of the new object.
    static final java.util.Map<String,String> CONSTRUCTORS=java.util.Map.of(
        "java/lang/String([B)V","java/lang/String","java/lang/String([C)V","java/lang/String",
        "java/lang/StringBuilder(Ljava/lang/String;)V","java/lang/StringBuilder","java/lang/StringBuilder(Ljava/lang/CharSequence;)V","java/lang/StringBuilder",
        "java/lang/StringBuffer(Ljava/lang/String;)V","java/lang/StringBuffer","java/lang/StringBuffer(Ljava/lang/CharSequence;)V","java/lang/StringBuffer");
    static final java.util.Map<String,Character> TRANSFORMS=java.util.Map.ofEntries(
        java.util.Map.entry("java/lang/String.getBytes()[B",'A'),
        java.util.Map.entry("java/lang/String.getBytes(Ljava/lang/String;)[B",'B'),
        java.util.Map.entry("java/lang/String.getBytes(Ljava/nio/charset/Charset;)[B",'B'),
        java.util.Map.entry("java/lang/String.toCharArray()[C",'A'),
        java.util.Map.entry("java/lang/String.split(Ljava/lang/String;)[Ljava/lang/String;",'B'),
        java.util.Map.entry("java/lang/String.valueOf([C)Ljava/lang/String;",'D'),
        java.util.Map.entry("java/net/URLDecoder.decode(Ljava/lang/String;)Ljava/lang/String;",'D'),
        java.util.Map.entry("java/net/URLDecoder.decode(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",'E'),
        java.util.Map.entry("java/net/URLDecoder.decode(Ljava/lang/String;Ljava/nio/charset/Charset;)Ljava/lang/String;",'E'),
        java.util.Map.entry("java/net/URLEncoder.encode(Ljava/lang/String;)Ljava/lang/String;",'D'),
        java.util.Map.entry("java/net/URLEncoder.encode(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",'E'),
        java.util.Map.entry("java/net/URLEncoder.encode(Ljava/lang/String;Ljava/nio/charset/Charset;)Ljava/lang/String;",'E'),
        java.util.Map.entry("java/util/Base64$Decoder.decode([B)[B",'C'),
        java.util.Map.entry("java/util/Base64$Decoder.decode(Ljava/lang/String;)[B",'C'),
        java.util.Map.entry("java/util/Base64$Encoder.encode([B)[B",'C'),
        java.util.Map.entry("java/util/Base64$Encoder.encodeToString([B)Ljava/lang/String;",'C'),
        java.util.Map.entry("org/apache/commons/codec/binary/Base64.decodeBase64([B)[B",'D'),
        java.util.Map.entry("org/apache/commons/codec/binary/Base64.decodeBase64(Ljava/lang/String;)[B",'D'),
        java.util.Map.entry("org/apache/commons/codec/binary/Base64.encodeBase64([B)[B",'D'),
        java.util.Map.entry("org/apache/commons/codec/binary/Base64.encodeBase64String([B)Ljava/lang/String;",'D'));
    // Types the application calls to read request input (interfaces and the standard wrappers, javax and jakarta).
    static final java.util.Set<String> SERVLET_REQUESTS=java.util.Set.of("javax/servlet/ServletRequest","javax/servlet/http/HttpServletRequest","javax/servlet/ServletRequestWrapper","javax/servlet/http/HttpServletRequestWrapper",
        "jakarta/servlet/ServletRequest","jakarta/servlet/http/HttpServletRequest","jakarta/servlet/ServletRequestWrapper","jakarta/servlet/http/HttpServletRequestWrapper");
    public static void install(Instrumentation instrumentation) {
        if(!Boolean.getBoolean("telvyn.iast.enabled"))return;
        String prefix=System.getProperty("telvyn.iast.application-package","");
        if(!prefix.matches("[a-zA-Z_$][\\w$]*(\\.[a-zA-Z_$][\\w$]*)+\\.")||prefix.startsWith("java.")||prefix.startsWith("system.monitoring.debugger."))throw new IllegalArgumentException("IAST application package must have at least two segments and end in a dot, e.g. com.company.");
        new AgentBuilder.Default().disableClassFormatChanges().with(new AgentBuilder.Listener.Adapter(){
            @Override public void onError(String name,ClassLoader loader,net.bytebuddy.utility.JavaModule module,boolean loaded,Throwable error){SecuritySensorState.iastFailed();LocalAttackReporter.reportLoss("IAST transformation failure");}
        }).type(nameStartsWith(prefix).and(not(nameStartsWith("system.monitoring.debugger."))).and(not(nameStartsWith("system.monitoring.security.")))
                // Classes generated at runtime (Hibernate/javassist and CGLIB proxies) are not application code.
                .and(not(nameContains("$$"))))
            .transform((builder,type,loader,module,domain)->builder.visit(new Calls()).visit(Advice.to(Source.class).on(isAnnotatedWith(namedOneOf("system.monitoring.security.InspectQuery","jakarta.ws.rs.GET","jakarta.ws.rs.POST","jakarta.ws.rs.PUT","jakarta.ws.rs.PATCH","jakarta.ws.rs.DELETE","jakarta.ws.rs.HEAD","jakarta.ws.rs.OPTIONS","org.springframework.web.bind.annotation.GetMapping","org.springframework.web.bind.annotation.PostMapping","org.springframework.web.bind.annotation.PutMapping","org.springframework.web.bind.annotation.PatchMapping","org.springframework.web.bind.annotation.DeleteMapping","org.springframework.web.bind.annotation.RequestMapping")).and(not(returns(void.class))))))
            .installOn(instrumentation);
        SecuritySensorState.iastInstalled();
    }
    public static class Source {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static Object enter(@Advice.Origin Method method,@Advice.AllArguments Object[] args){return IastRuntime.enter(method,args);}
        @Advice.OnMethodExit(onThrowable=Throwable.class,suppress=Throwable.class) public static void exit(@Advice.Enter Object previous,@Advice.Return(readOnly=false,typing=net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC)Object result,@Advice.Thrown Throwable error){Object context=IastRuntime.capture();if(context!=previous)result=IastAsync.returned(result,context,error);IastRuntime.exit(previous);}
    }
    private static class Calls extends AsmVisitorWrapper.AbstractBase {
        @Override public int mergeWriter(int flags){return flags|ClassWriter.COMPUTE_MAXS;}
        @Override public ClassVisitor wrap(TypeDescription type,ClassVisitor visitor,Implementation.Context context,TypePool pool,FieldList<FieldDescription.InDefinedShape> fields,MethodList<?> methods,int writer,int reader) {
            return new ClassVisitor(Opcodes.ASM9,visitor){
                final java.util.Map<String,Boolean> repositories=new java.util.HashMap<>();
                final java.util.Map<String,Boolean> executors=new java.util.HashMap<>();
                boolean executor(String owner){return executors.computeIfAbsent(owner,key->{var resolution=pool.describe(key.replace('/','.'));return resolution.isResolved()&&hasSuperType(named("java.util.concurrent.Executor")).matches(resolution.resolve());});}
                boolean panache(String owner){return repositories.computeIfAbsent(owner,key->{
                    var resolution=pool.describe(key.replace('/','.'));
                    return resolution.isResolved()&&hasSuperType(named("io.quarkus.hibernate.orm.panache.PanacheRepositoryBase")).matches(resolution.resolve());
                });}
                @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){
                    return new MethodVisitor(Opcodes.ASM9,super.visitMethod(access,name,descriptor,signature,exceptions)){
                        int line;
                        final String runtime="system/monitoring/debugger/IastRuntime";
                        @Override public void visitLineNumber(int number,Label label){line=number;super.visitLineNumber(number,label);}
                        // Report hooks: copy the argument that matters, add where we are, and hand it to the runtime. Values stay on the stack of the application; only a copy of the reference is inspected.
                        void report(int copy,boolean dropLast,String hook,String descriptor,String owner,String method){
                            super.visitInsn(copy==1?Opcodes.DUP:Opcodes.DUP2);if(dropLast)super.visitInsn(Opcodes.POP);
                            super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                            super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,hook,descriptor,false);
                        }
                        @Override public void visitInvokeDynamicInsn(String method,String desc,Handle bootstrap,Object... args){
                            if(bootstrap.getOwner().equals("java/lang/invoke/StringConcatFactory")&&bootstrap.getName().equals("makeConcatWithConstants"))
                                bootstrap=new Handle(Opcodes.H_INVOKESTATIC,runtime,"concatFactory",bootstrap.getDesc(),false);
                            super.visitInvokeDynamicInsn(method,desc,bootstrap,args);
                        }
                        @Override public void visitMethodInsn(int opcode,String owner,String method,String desc,boolean itf){
                            // Servlet inputs: the value the application reads is marked with the name it asked for.
                            if(SERVLET_REQUESTS.contains(owner)){
                                String hook=switch(method+desc){
                                    case "getParameter(Ljava/lang/String;)Ljava/lang/String;"->"sourceParameter";
                                    case "getHeader(Ljava/lang/String;)Ljava/lang/String;"->"sourceHeader";
                                    case "getParameterValues(Ljava/lang/String;)[Ljava/lang/String;"->"sourceParameterValues";
                                    case "getHeaders(Ljava/lang/String;)Ljava/util/Enumeration;"->"sourceHeaders";
                                    default->null;
                                };
                                if(hook!=null){
                                    // [request, name] -> [name, request, name] -> call -> [name, value] -> marked value
                                    super.visitInsn(Opcodes.DUP_X1);super.visitMethodInsn(opcode,owner,method,desc,itf);
                                    String result=desc.substring(desc.indexOf(')')+1);
                                    super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,hook,"(Ljava/lang/String;"+result+")"+result,false);return;
                                }
                                if(method.equals("getParameterMap")&&desc.equals("()Ljava/util/Map;")){super.visitMethodInsn(opcode,owner,method,desc,itf);super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"sourceParameterMap","(Ljava/util/Map;)Ljava/util/Map;",false);return;}
                                if(method.equals("getQueryString")&&desc.equals("()Ljava/lang/String;")){super.visitMethodInsn(opcode,owner,method,desc,itf);super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"sourceQuery","(Ljava/lang/String;)Ljava/lang/String;",false);return;}
                                if((method.equals("getParameterNames")||method.equals("getHeaderNames"))&&desc.equals("()Ljava/util/Enumeration;")){
                                    super.visitMethodInsn(opcode,owner,method,desc,itf);super.visitLdcInsn(method.equals("getParameterNames")?"parametername":"headername");super.visitInsn(Opcodes.SWAP);
                                    super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"sourceNames","(Ljava/lang/String;Ljava/util/Enumeration;)Ljava/util/Enumeration;",false);return;
                                }
                            }
                            // Transformations that keep the origin of their input: the result is marked like its source.
                            Character sanitizer=XSS_SANITIZERS.get(owner+"."+method+desc);
                            Character shape=sanitizer!=null?sanitizer:TRANSFORMS.get(owner+"."+method+desc);
                            if(shape!=null){
                                String result=desc.substring(desc.indexOf(')')+1);
                                switch(shape){
                                    case 'A'->super.visitInsn(Opcodes.DUP);                                                   // source is the receiver, no argument
                                    case 'B'->{super.visitInsn(Opcodes.SWAP);super.visitInsn(Opcodes.DUP_X1);super.visitInsn(Opcodes.SWAP);} // receiver, one argument
                                    case 'C'->super.visitInsn(Opcodes.DUP_X1);                                                // the single argument of an instance call
                                    case 'D'->super.visitInsn(Opcodes.DUP);                                                   // the single argument of a static call
                                    case 'E'->{super.visitInsn(Opcodes.SWAP);super.visitInsn(Opcodes.DUP_X1);super.visitInsn(Opcodes.SWAP);} // first of two static arguments
                                    default->{}
                                }
                                super.visitMethodInsn(opcode,owner,method,desc,itf);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,sanitizer!=null?"sanitizeXss":"propagateFrom","(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",false);
                                super.visitTypeInsn(Opcodes.CHECKCAST,result.startsWith("[")?result:result.substring(1,result.length()-1));
                                return;
                            }
                            // new String(byte[] | char[] [, charset]) and new StringBuilder/StringBuffer(text): the new object keeps the origin.
                            String created=method.equals("<init>")?CONSTRUCTORS.get(owner+desc):null;
                            if(created!=null||owner.equals("java/lang/String")&&method.equals("<init>")&&(desc.equals("([BLjava/lang/String;)V")||desc.equals("([BLjava/nio/charset/Charset;)V"))){
                                if(created!=null){
                                    // [s, s, array] -> [array, s, s, array] -> init -> [array, s]
                                    super.visitInsn(Opcodes.DUP_X2);super.visitMethodInsn(opcode,owner,method,desc,itf);
                                } else {
                                    // [s, s, array, charset] -> [array, charset, s, s, array, charset] -> init -> [array, charset, s] -> [array, s]
                                    super.visitInsn(Opcodes.DUP2_X2);super.visitMethodInsn(opcode,owner,method,desc,itf);
                                    super.visitInsn(Opcodes.SWAP);super.visitInsn(Opcodes.POP);
                                }
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"propagateFrom","(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",false);
                                super.visitTypeInsn(Opcodes.CHECKCAST,created!=null?created:"java/lang/String");
                                return;
                            }
                            if((owner.equals("javax/servlet/http/Cookie")||owner.equals("jakarta/servlet/http/Cookie"))&&method.equals("getValue")&&desc.equals("()Ljava/lang/String;")){
                                super.visitInsn(Opcodes.DUP);super.visitMethodInsn(opcode,owner,method,desc,itf);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"sourceCookie","(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;",false);return;
                            }
                            boolean webTask=owner.equals("org/springframework/web/context/request/async/WebAsyncTask")&&method.equals("<init>")&&desc.endsWith("Ljava/util/concurrent/Callable;)V");
                            boolean submitted=method.equals("submit")&&executor(owner);
                            if(webTask||submitted&&desc.startsWith("(Ljava/util/concurrent/Callable;)"))super.visitMethodInsn(Opcodes.INVOKESTATIC,"system/monitoring/debugger/IastAsync","taskCallable","(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Callable;",false);
                            if((method.equals("execute")&&executor(owner)||submitted)&&(desc.startsWith("(Ljava/lang/Runnable;)")||desc.startsWith("(Ljava/lang/Runnable;Ljava/lang/Object;)"))){
                                boolean withResult=desc.startsWith("(Ljava/lang/Runnable;Ljava/lang/Object;)");
                                if(withResult)super.visitInsn(Opcodes.SWAP);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,"system/monitoring/debugger/IastAsync","taskRunnable","(Ljava/lang/Runnable;)Ljava/lang/Runnable;",false);
                                if(withResult)super.visitInsn(Opcodes.SWAP);
                            }
                            if(owner.equals("java/util/concurrent/CompletableFuture")&&(method.equals("supplyAsync")||method.equals("runAsync"))) {super.visitMethodInsn(Opcodes.INVOKESTATIC,"system/monitoring/debugger/IastAsync",method,desc,false);return;}
                            if(owner.equals("java/util/concurrent/CompletableFuture")&&method.equals("thenApplyAsync")){super.visitMethodInsn(Opcodes.INVOKESTATIC,"system/monitoring/debugger/IastAsync",method,"(Ljava/util/concurrent/CompletableFuture;"+desc.substring(1),false);return;}
                            boolean r2dbcSpi=owner.equals("io/r2dbc/spi/Connection")&&method.equals("createStatement");
                            boolean r2dbcClient=owner.equals("org/springframework/r2dbc/core/DatabaseClient")&&method.equals("sql");
                            if((r2dbcSpi||r2dbcClient)&&desc.startsWith("(Ljava/lang/String;)")){
                                super.visitInsn(Opcodes.DUP);super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"r2dbc","(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V",false);
                            }
                            if(r2dbcClient&&desc.startsWith("(Ljava/util/function/Supplier;)")){
                                super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"r2dbcSupplier","(Ljava/util/function/Supplier;Ljava/lang/String;ILjava/lang/String;)Ljava/util/function/Supplier;",false);
                            }
                            // Only SQL text overloads; PreparedStatement parameter values are never SQL sinks.
                            if(((owner.equals("java/sql/Statement")&&(method.equals("execute")||method.equals("executeQuery")||method.equals("executeUpdate")||method.equals("addBatch")))||(owner.equals("java/sql/Connection")&&(method.equals("prepareStatement")||method.equals("prepareCall"))))&&desc.startsWith("(Ljava/lang/String;)")) {
                                super.visitInsn(Opcodes.DUP);super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"jdbc","(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V",false);
                            }
                            if(owner.equals("java/lang/String")&&method.equals("concat")&&desc.equals("(Ljava/lang/String;)Ljava/lang/String;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"concat","(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",false);return;}
                            if(owner.equals("java/lang/String")&&(method.equals("trim")||method.equals("toLowerCase"))&&desc.equals("()Ljava/lang/String;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,method,"(Ljava/lang/String;)Ljava/lang/String;",false);return;}
                            boolean single=desc.startsWith("(Ljava/lang/String;)");
                            boolean typed=desc.startsWith("(Ljava/lang/String;Ljava/lang/Class;)");
                            boolean jpa=owner.equals("jakarta/persistence/EntityManager")&&(method.equals("createQuery")||method.equals("createNativeQuery"))&&(single||typed);
                            boolean repository=(method.equals("list")||method.equals("find")||method.equals("count"))&&desc.startsWith("(Ljava/lang/String;[Ljava/lang/Object;)")&&panache(owner);
                            if(jpa||repository){
                                // Duplicate only query text; bound parameters and result types are not sources.
                                super.visitInsn(single?Opcodes.DUP:Opcodes.DUP2);
                                if(!single)super.visitInsn(Opcodes.POP);
                                super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"orm","(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V",false);
                            }
                            final String one="(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V",two="(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V";
                            final boolean constructor=method.equals("<init>");
                            // XSS, LDAP and XPath: the call is replaced by a bridge that inspects the argument and makes the same call.
                            String bridge=BRIDGES.get(owner+"."+method+desc);
                            if(bridge!=null){
                                super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,"system/monitoring/debugger/IastBridges",method,"("+bridge+desc.substring(1,desc.indexOf(')'))+"Ljava/lang/String;I)"+desc.substring(desc.indexOf(')')+1),false);
                                return;
                            }
                            // The writer of the HTTP response is remembered, so that only it is an XSS sink.
                            if(SERVLET_RESPONSES.contains(owner)&&method.equals("getWriter")&&desc.equals("()Ljava/io/PrintWriter;")){
                                super.visitMethodInsn(opcode,owner,method,desc,itf);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"responseWriter","(Ljava/lang/Object;)Ljava/lang/Object;",false);
                                super.visitTypeInsn(Opcodes.CHECKCAST,"java/io/PrintWriter");return;
                            }
                            // Trust boundary: request input stored in the session, as the attribute name or its value.
                            if((owner.equals("javax/servlet/http/HttpSession")||owner.equals("jakarta/servlet/http/HttpSession"))&&(method.equals("setAttribute")||method.equals("putValue"))&&desc.equals("(Ljava/lang/String;Ljava/lang/Object;)V"))
                                report(2,false,"trustBoundary","(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)V",owner,method);
                            // Weak randomness: java.util.Random itself (not SecureRandom) and Math.random, inside a request.
                            if(owner.equals("java/util/Random")&&constructor&&(desc.equals("()V")||desc.equals("(J)V"))||owner.equals("java/lang/Math")&&method.equals("random")&&desc.equals("()D")){
                                super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"weakRandom","(Ljava/lang/String;ILjava/lang/String;)V",false);
                            }
                            // Command execution: the command or its arguments came from the request.
                            if(owner.equals("java/lang/Runtime")&&method.equals("exec")){
                                if(desc.startsWith("(Ljava/lang/String;)")||desc.startsWith("([Ljava/lang/String;)"))report(1,false,"command",one,owner,method);
                                // Command and environment: an injected "NAME=value" is as dangerous as the command itself.
                                else if(desc.equals("(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;")||desc.equals("([Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;"))report(2,false,"command",two,owner,method);
                                else if(desc.equals("(Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;")||desc.equals("([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;")){
                                    // [runtime, command, environment, directory] -> [runtime, command, environment, directory, command, environment]
                                    super.visitInsn(Opcodes.DUP_X2);super.visitInsn(Opcodes.POP);super.visitInsn(Opcodes.DUP2_X1);
                                    super.visitLdcInsn(type.getName()+"#"+name);super.visitLdcInsn(line);super.visitLdcInsn(owner.replace('/','.')+"."+method);
                                    super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"command",two,false);
                                }
                            }
                            if(owner.equals("java/lang/ProcessBuilder")&&(constructor||method.equals("command"))&&(desc.startsWith("([Ljava/lang/String;)")||desc.startsWith("(Ljava/util/List;)")))report(1,false,"command",one,owner,method);
                            // File paths: construction of the file or path object, the way the JDK API is used.
                            if(constructor&&(owner.equals("java/io/File")||owner.equals("java/io/FileInputStream")||owner.equals("java/io/FileOutputStream")||owner.equals("java/io/FileReader")||owner.equals("java/io/FileWriter"))){
                                if(desc.equals("(Ljava/lang/String;)V")||owner.equals("java/io/File")&&desc.equals("(Ljava/io/File;Ljava/lang/String;)V"))report(1,false,"path",one,owner,"<init>");
                                else if(owner.equals("java/io/File")&&desc.equals("(Ljava/lang/String;Ljava/lang/String;)V"))report(2,false,"path",two,owner,"<init>");
                                else if(!owner.equals("java/io/File")&&desc.equals("(Ljava/lang/String;Z)V"))report(2,true,"path",one,owner,"<init>");
                            }
                            if((owner.equals("java/nio/file/Paths")&&method.equals("get")||owner.equals("java/nio/file/Path")&&method.equals("of"))&&desc.startsWith("(Ljava/lang/String;[Ljava/lang/String;)"))report(2,false,"path",two,owner,method);
                            // A path given as a URI: the URI keeps the origin of its text (IastJdk).
                            if(constructor&&owner.equals("java/io/File")&&desc.equals("(Ljava/net/URI;)V"))report(1,false,"path",one,owner,"<init>");
                            if((owner.equals("java/nio/file/Paths")&&method.equals("get")||owner.equals("java/nio/file/Path")&&method.equals("of"))&&desc.equals("(Ljava/net/URI;)Ljava/nio/file/Path;"))report(1,false,"path",one,owner,method);
                            // Outgoing requests: the URL is built from request input.
                            if(owner.equals("java/net/URL")&&constructor&&desc.equals("(Ljava/lang/String;)V")||owner.equals("java/net/URI")&&(constructor&&desc.equals("(Ljava/lang/String;)V")||method.equals("create")&&desc.startsWith("(Ljava/lang/String;)")))report(1,false,"ssrf",one,owner,constructor?"<init>":method);
                            // Code evaluation, redirects and response headers built from request input.
                            if(owner.equals("javax/script/ScriptEngine")&&method.equals("eval")){
                                if(desc.startsWith("(Ljava/lang/String;)"))report(1,false,"code",one,owner,method);
                                else if(desc.startsWith("(Ljava/lang/String;Ljavax/script/"))report(2,true,"code",one,owner,method);
                            }
                            if(owner.equals("groovy/lang/GroovyShell")&&(method.equals("evaluate")||method.equals("parse"))&&desc.startsWith("(Ljava/lang/String;)"))report(1,false,"code",one,owner,method);
                            if(owner.equals("org/springframework/expression/ExpressionParser")&&method.equals("parseExpression")){
                                if(desc.startsWith("(Ljava/lang/String;)"))report(1,false,"code",one,owner,method);
                                else if(desc.startsWith("(Ljava/lang/String;Lorg/springframework/expression/ParserContext;)"))report(2,true,"code",one,owner,method);
                            }
                            // A filter or document written as JSON text and parsed by the MongoDB driver.
                            if(method.equals("parse")&&(owner.equals("org/bson/Document")||owner.equals("com/mongodb/BasicDBObject")||owner.equals("org/bson/BsonDocument"))){
                                if(desc.startsWith("(Ljava/lang/String;)"))report(1,false,"nosql",one,owner,method);
                                else if(desc.startsWith("(Ljava/lang/String;Lorg/bson/codecs/Decoder;)"))report(2,true,"nosql",one,owner,method);
                            }
                            final boolean servletResponse=owner.equals("jakarta/servlet/http/HttpServletResponse")||owner.equals("javax/servlet/http/HttpServletResponse");
                            if(servletResponse&&method.equals("sendRedirect")&&desc.startsWith("(Ljava/lang/String;)"))report(1,false,"redirect",one,owner,method);
                            if(owner.equals("org/springframework/web/servlet/view/RedirectView")&&constructor){
                                if(desc.equals("(Ljava/lang/String;)V"))report(1,false,"redirect",one,owner,"<init>");
                                else if(desc.equals("(Ljava/lang/String;Z)V"))report(2,true,"redirect",one,owner,"<init>");
                            }
                            // Only the value of a header can carry injected line breaks.
                            if(servletResponse&&(method.equals("setHeader")||method.equals("addHeader"))&&desc.equals("(Ljava/lang/String;Ljava/lang/String;)V"))report(1,false,"header",one,owner,method);
                            // Weak algorithms and cookies without protection: no input is needed, only the call.
                            if(owner.equals("java/security/MessageDigest")&&method.equals("getInstance")){
                                if(desc.startsWith("(Ljava/lang/String;)"))report(1,false,"weakHash",one,owner,method);
                                else if(desc.startsWith("(Ljava/lang/String;Ljava/"))report(2,true,"weakHash",one,owner,method);
                            }
                            if(owner.equals("javax/crypto/Cipher")&&method.equals("getInstance")){
                                if(desc.startsWith("(Ljava/lang/String;)"))report(1,false,"weakCipher",one,owner,method);
                                else if(desc.startsWith("(Ljava/lang/String;Ljava/"))report(2,true,"weakCipher",one,owner,method);
                            }
                            if(servletResponse&&method.equals("addCookie")&&desc.startsWith("(Ljakarta/servlet/http/Cookie;)")||servletResponse&&method.equals("addCookie")&&desc.startsWith("(Ljavax/servlet/http/Cookie;)"))report(1,false,"cookie",one,owner,method);
                            // Propagation through the String and StringBuilder calls the application makes.
                            if(owner.equals("java/lang/String")&&(method.equals("strip")||method.equals("toUpperCase"))&&desc.equals("()Ljava/lang/String;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,method,"(Ljava/lang/String;)Ljava/lang/String;",false);return;}
                            if(owner.equals("java/lang/String")&&method.equals("substring")&&(desc.equals("(I)Ljava/lang/String;")||desc.equals("(II)Ljava/lang/String;"))) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,method,"(Ljava/lang/String;"+desc.substring(1),false);return;}
                            if(owner.equals("java/lang/String")&&method.equals("replace")&&desc.equals("(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"replace","(Ljava/lang/String;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;",false);return;}
                            if(owner.equals("java/lang/StringBuilder")&&method.equals("append")&&desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"append","(Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/StringBuilder;",false);return;}
                            if(owner.equals("java/lang/StringBuffer")&&method.equals("append")&&desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuffer;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"append","(Ljava/lang/StringBuffer;Ljava/lang/String;)Ljava/lang/StringBuffer;",false);return;}
                            if(owner.equals("java/lang/StringBuilder")&&method.equals("toString")&&desc.equals("()Ljava/lang/String;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"builderToString","(Ljava/lang/StringBuilder;)Ljava/lang/String;",false);return;}
                            if(owner.equals("java/lang/StringBuffer")&&method.equals("toString")&&desc.equals("()Ljava/lang/String;")) {super.visitMethodInsn(Opcodes.INVOKESTATIC,runtime,"bufferToString","(Ljava/lang/StringBuffer;)Ljava/lang/String;",false);return;}
                            super.visitMethodInsn(opcode,owner,method,desc,itf);
                        }
                    };
                }
            };
        }
    }
}
