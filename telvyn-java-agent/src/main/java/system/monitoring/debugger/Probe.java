package system.monitoring.debugger;

import java.util.ArrayList;
import java.util.List;

/**
 * Um "probe": qual método fotografar. v1 identifica por {@code classe#metodo}.
 * Config vem como lista separada por vírgula, ex.:
 *   {@code com.exemplo.PedidoService#cobrar,com.exemplo.Pagamento#processar}
 */
public final class Probe {
    public final String className;
    public final String methodName;
    public final int line;

    private Probe(String className, String methodName,int line) {
        this.className = className;
        this.methodName = methodName;
        this.line=line;
    }

    /** Parseia "classe#metodo,classe#metodo" → lista de probes (ignora entradas inválidas). */
    public static List<Probe> parse(String spec) {
        List<Probe> out = new ArrayList<>();
        if (spec == null) return out;
        for (String raw : spec.split(",")) {
            String s = raw.trim();
            if (s.isEmpty()) continue;
            int hash = s.indexOf('#');
            if (hash <= 0 || hash >= s.length() - 1) continue; // precisa de classe#metodo
            String cls = s.substring(0, hash).trim();
            String mtd = s.substring(hash + 1).trim();
            int line=0,at=mtd.lastIndexOf('@');if(at>=0){try{line=Integer.parseInt(mtd.substring(at+1));if(line<1||line>1000000)continue;mtd=mtd.substring(0,at);}catch(NumberFormatException invalid){continue;}}
            if (!cls.isEmpty() && !mtd.isEmpty()) {
                out.add(new Probe(cls, mtd,line));
            }
        }
        return out;
    }

    @Override
    public String toString() {
        return className + "#" + methodName+(line>0?"@"+line:"");
    }
}
