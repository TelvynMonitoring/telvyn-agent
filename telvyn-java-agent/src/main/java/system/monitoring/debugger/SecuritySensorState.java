package system.monitoring.debugger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Runtime registration only; never infers coverage from traffic or findings. */
public final class SecuritySensorState {
    private static final Map<String,String> state=sharedRegistry();
    private SecuritySensorState() {}
    // Quarkus and the premain agent can load separate copies; use the agent's JVM registry.
    private static Map<String,String> sharedRegistry(){
        var system=ClassLoader.getSystemClassLoader();
        if(SecuritySensorState.class.getClassLoader()!=system)try{
            return (Map<String,String>)Class.forName(SecuritySensorState.class.getName(),true,system).getMethod("registry").invoke(null);
        }catch(ReflectiveOperationException unavailable){ /* No premain agent in this JVM. */ }
        return new ConcurrentHashMap<>();
    }
    public static Map<String,String> registry(){return state;}
    public static void attack(boolean enabled){if(!"error".equals(state.get("attack")))state.put("attack",enabled?"active":"disabled");}
    public static void attackStopped(){state.put("attack","absent");}
    public static void attackFailed(){state.put("attack","error");}
    public static void iastInstalled(){state.put("iastInstalled","true");}
    public static void iastFailed(){state.put("iastFailed","true");}
    public static void iastIntegration(boolean registered){state.put("iastIntegration",Boolean.toString(registered));}
    public static String attack(){return state.getOrDefault("attack","absent");}
    public static String iast(){
        if(!Boolean.getBoolean("telvyn.iast.enabled")||Boolean.FALSE.equals(RemoteConfig.security("iast")))return "disabled";
        if("true".equals(state.get("iastFailed")))return "error";
        return "true".equals(state.get("iastInstalled"))&&"true".equals(state.get("iastIntegration"))?"active":"absent";
    }
}
