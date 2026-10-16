package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * SQL text reaching any JDBC driver: every overload whose first argument is the SQL (prepareStatement(sql, type, concurrency),
 * execute(sql, keys)...), and frameworks that build the text before the driver (JdbcTemplate). The call sites in application
 * code only cover the one-argument forms. Works only inside a request scope; the finding is placed at the first application frame.
 */
public final class JdbcIast {
    private JdbcIast() {}
    public static void install(Instrumentation instrumentation){
        if(!Boolean.getBoolean("telvyn.iast.enabled"))return;
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(not(isInterface()).and(not(nameStartsWith("system.monitoring."))).and(isSubTypeOf(java.sql.Connection.class).or(isSubTypeOf(java.sql.Statement.class))))
            .transform((builder,type,loader,module,domain)->builder.visit(Advice.to(Sql.class).on(isPublic().and(not(isAbstract()))
                .and(namedOneOf("prepareStatement","prepareCall","execute","executeQuery","executeUpdate","executeLargeUpdate","addBatch"))
                .and(takesArgument(0,String.class)))))
            .installOn(instrumentation);
    }
    public static void inspect(String sql,String origin){
        if(sql==null||IastRuntime.capture()==null)return;
        SpringMvcSecurity.jdbc(sql,origin);
    }
    public static class Sql {
        @Advice.OnMethodEnter(suppress=Throwable.class) public static void enter(@Advice.Argument(0)String sql,@Advice.Origin("#t.#m")String origin){inspect(sql,origin);}
    }
}
