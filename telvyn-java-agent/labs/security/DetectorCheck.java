import system.monitoring.debugger.LocalAttackDetection;

/** Single diagnostic for the packaged engine; no HTTP, credentials or persisted requests. */
public class DetectorCheck {
    public static void main(String[] args) {
        try(var detector=new LocalAttackDetection()) {
            var allowed=java.util.Set.of("q","search");
            var selected=LocalAttackDetection.permittedQuery("search=1+OR+1%3D1+--&ignored=%ZZ",allowed);
            if(!selected.keySet().equals(java.util.Set.of("search")))throw new AssertionError("Allowlist leaked another field");
            if(!detector.inspectPermittedQuery(selected).outcome().equals("match"))throw new AssertionError("Generic allowed parameter not inspected");
            try{LocalAttackDetection.permittedQuery("q=first&%71=second",allowed);throw new AssertionError("Encoded duplicate accepted");}catch(LocalAttackDetection.InputLimitException expected){}
            try{LocalAttackDetection.permittedQuery("q="+"a".repeat(2049),allowed);throw new AssertionError("Input bound missing");}catch(LocalAttackDetection.InputLimitException expected){}
        }
        try(var detector=new LocalAttackDetection()) {
            var off=detector.inspectSearchQuery(false,"<script>alert(1)</script>");
            if(!off.outcome().equals("disabled")||off.engine_version()!=null)throw new AssertionError("Disabled detector loaded native engine");
            String[] values={"hello world","1 OR 1=1 --","<script>alert(1)</script>"};
            String[] expected={"no_match","match","match"};
            for(int i=0;i<values.length;i++) {
                var result=detector.inspectSearchQuery(true,values[i]);
                if(!result.outcome().equals(expected[i]))throw new AssertionError("Unexpected outcome in case "+i+": "+result.outcome());
                if(result.toString().contains(values[i]))throw new AssertionError("Raw value escaped result");
                System.out.println("case="+i+" outcome="+result.outcome()+" engine="+result.engine_version()+" elapsed_us="+result.elapsed_us());
            }
            if(!detector.inspectSearchQuery(true,"a".repeat(2049)).outcome().equals("limit"))throw new AssertionError("Missing input bound");
            String[] queries={"q=hello", "q=1+OR+1%3D1+--", "other=%ZZ", "q=%ZZ", "q=hello&q=second"};
            String[] outcomes={"no_match", "match", "no_match", "error", "limit"};
            for(int i=0;i<queries.length;i++) {
                if(!detector.inspectSearchRequest(true,queries[i]).outcome().equals(outcomes[i]))throw new AssertionError("Query boundary case "+i);
                if(!detector.inspectSearchRequest(false,queries[i]).outcome().equals("disabled"))throw new AssertionError("Disabled query was inspected");
            }
        }
    }
}
