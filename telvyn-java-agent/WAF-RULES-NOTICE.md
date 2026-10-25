Telvyn WAF rules (src/main/resources/telvyn/waf-rules.json)

The attack detection rules are generated from the OWASP Core Rule Set (CRS) by tools/crs-convert/convert.py
(rules of the REQUEST-911 to REQUEST-944 files, paranoia levels 1 and 2). Copyright the OWASP CRS project contributors,
licensed under Apache-2.0 (META-INF/licenses/owasp-crs/LICENSE, https://github.com/coreruleset/coreruleset).

The API Security scanners (payment, personal data and credentials) are Telvyn's own (tools/crs-convert/api-schema.json).

SQL injection and XSS operators run libinjection, compiled unmodified to WebAssembly (tools/libinjection-wasm) and
executed by Chicory. Copyright (c) 2012-2016 Nick Galbreath and (c) 2017-2024 libinjection Contributors, BSD 3-Clause
(META-INF/licenses/libinjection/COPYING). Chicory is Apache-2.0 (META-INF/licenses/chicory/LICENSE).

Rule modes (block, monitor, off) are decided by the Telvyn rule modes set in the UI.
