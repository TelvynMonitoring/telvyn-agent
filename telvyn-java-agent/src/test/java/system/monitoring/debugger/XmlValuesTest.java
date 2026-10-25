package system.monitoring.debugger;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

class XmlValuesTest {
    @Test
    void textoAtributosECdataComEntidadesDecodificadas() {
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><r a=\"&lt;script&gt;\"><i>&#60;b&#x3e;</i><![CDATA[ x' or 1=1 ]]></r>";
        assertEquals(List.of("<script>", "<b>", " x' or 1=1 "), WafInspector.xmlValues(xml));
    }
}
