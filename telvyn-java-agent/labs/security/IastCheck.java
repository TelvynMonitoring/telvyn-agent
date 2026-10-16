package system.monitoring.securitylab;

import jakarta.ws.rs.QueryParam;
import system.monitoring.security.InspectQuery;
import system.monitoring.debugger.IastRuntime;
import java.sql.DriverManager;
import java.util.ArrayList;

/** Focused provenance diagnostic; run with assertions and the explicitly scoped Javaagent. */
public class IastCheck {
    @InspectQuery({"q"}) public static java.util.List<Integer> list(@QueryParam("q") String q,String mode)throws Exception {
        q=q.trim().toLowerCase();
        try(var connection=DriverManager.getConnection("jdbc:h2:mem:provenance")){
            if(mode.equals("exception"))throw new IllegalStateException("controlled exception");
            if(mode.equals("parameterized"))try(var statement=connection.prepareStatement("SELECT 1 WHERE ? = 'sample'")){statement.setString(1,q);try(var rows=statement.executeQuery()){rows.next();}}
            else try(var statement=connection.createStatement();var rows=statement.executeQuery("SELECT 1 WHERE '"+q+"' = 'sample'")){rows.next();}
        }
        return java.util.List.of(1);
    }
    @InspectQuery({"q"}) public static String query(@QueryParam("q") String q,String mode)throws Exception {
        try(var connection=DriverManager.getConnection("jdbc:h2:mem:provenance")){
            if(mode.equals("parameterized"))try(var statement=connection.prepareStatement("SELECT 1 WHERE ? = 'sample'")){statement.setString(1,q);try(var rows=statement.executeQuery()){rows.next();}}
            else if(mode.equals("constant"))try(var statement=connection.createStatement();var rows=statement.executeQuery("SELECT 1 WHERE 'sample' = 'sample'")){rows.next();}
            else if(mode.equals("prepared-concat"))try(var statement=connection.prepareStatement("SELECT 1 WHERE '"+q+"' = 'sample'");var rows=statement.executeQuery()){rows.next();}
            else if(mode.equals("exception"))throw new IllegalStateException("controlled exception");
            else {String sql=mode.equals("concat")?"SELECT 1 WHERE '".concat(q).concat("' = 'sample'"):"SELECT 1 WHERE '"+q+"' = 'sample'";try(var statement=connection.createStatement();var rows=statement.executeQuery(sql)){rows.next();}}
        }
        return "completed";
    }
    public static void main(String[] args)throws Exception {
        var findings=new ArrayList<IastRuntime.Finding>();IastRuntime.configure(findings::add);
        list(new String(" SAMPLE "),"concatenated");assert findings.size()==1:"List and normalization must preserve unsafe flow";
        list(new String(" SAMPLE "),"parameterized");assert findings.size()==1:"List bound parameter must remain safe";
        try{list(new String("sample"),"exception");throw new AssertionError();}catch(IllegalStateException expected){}
        IastRuntime.jdbc("sample","must.not#appear",1,"test.Sink");assert findings.size()==1:"List exception must clear scope";
        findings.clear();
        query(new String("sample"),"concatenated");assert findings.size()==1:"ordinary input must expose unsafe flow";
        assert findings.get(0).method().endsWith("IastCheck#query")&&findings.get(0).line()!=null;
        var first=findings.get(0);
        assert first.sink()!=null&&first.sink().endsWith("Statement.executeQuery"):"sink names the instrumented API";
        assert first.sql()!=null&&first.sql().contains("<redacted>")&&!first.sql().toLowerCase().contains("sample"):"statement is masked";
        assert first.stack()!=null&&!first.stack().isEmpty()&&first.stack().get(0).contains("IastCheck.query"):"stack starts at the application frame";
        assert first.stack().stream().noneMatch(frame->frame.startsWith("system.monitoring.debugger.")):"agent frames are left out";
        query(new String("sample"),"constant");assert findings.size()==1:"equal constant is not tainted";
        query("' OR 1=1 --","parameterized");assert findings.size()==1:"bound parameter is not SQL text";
        query(new String("sample"),"concat");assert findings.size()==2:"String.concat propagation";
        try{query(new String("sample"),"exception");throw new AssertionError();}catch(IllegalStateException expected){}
        IastRuntime.jdbc("sample","must.not#appear",1,"test.Sink");assert findings.size()==2:"scope must clear on exception";
        query(new String("sample"),"prepared-concat");assert findings.size()==3:"prepared SQL text remains unsafe when concatenated";
        query("x".repeat(2049),"concatenated");assert findings.size()==3:"source bound";
        IastRuntime.configure(null);query(new String("sample"),"concatenated");assert findings.size()==3:"disabled reporter";
        System.out.println("IAST provenance: concatenation, identity, bound parameters, source line, sink, masked statement, stack, exception cleanup and disabled passed");
    }
}
