Telvyn WAF rules (waf-rules.json)

The attack detection rules are generated from the OWASP Core Rule Set (CRS) by tools/crs-convert/convert.py
(rules of the REQUEST-911 to REQUEST-944 files, all paranoia levels; the agent loads up to the configured level, 2 by default). Copyright the OWASP CRS project contributors,
licensed under Apache-2.0 (licenses/owasp-crs/LICENSE, https://github.com/coreruleset/coreruleset).

Rules with the tlv- and rasp- prefixes (scanner and out-of-band hosts, SSRF, template and expression injection, scan detection by response status, exploit prevention) are Telvyn's own (tools/crs-convert/telvyn_rules.py, rasp-rules.json).

The API Security scanners (payment, personal data and credentials) and the exploit prevention rules (rasp-*) are
Telvyn's own (tools/crs-convert/api-schema.json, tools/crs-convert/rasp-rules.json).

SQL injection and XSS operators run libinjection, compiled unmodified to WebAssembly (libinjection.wasm, built by
tools/libinjection-wasm) and executed by Node.js's built-in WebAssembly. Copyright (c) 2012-2016 Nick Galbreath and
(c) 2017-2024 libinjection Contributors, BSD 3-Clause (licenses/libinjection/COPYING).

Rule modes (block, monitor, off) are decided by the Telvyn rule modes set in the UI.
