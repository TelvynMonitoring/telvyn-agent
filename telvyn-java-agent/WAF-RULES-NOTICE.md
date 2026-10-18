Telvyn WAF rules (waf-rules.json)

The attack detection rules are the Datadog App and API Protection recommended ruleset
(rules_version 1.18.0), taken from dd-trace-js (packages/dd-trace/src/appsec/recommended.json),
Copyright Datadog, Inc. Licensed under Apache-2.0 OR BSD-3-Clause
(https://github.com/DataDog/dd-trace-js/blob/master/LICENSE).

Changes by Telvyn: removed the IP and user blocking rules (blk-001-*), rules_compat, the
fingerprint and JWT processors, and the "block" actions; blocking is decided by the Telvyn rule
modes set in the UI. The API security schema processors (extract-content, extract-headers) and
the scanners are kept as published.
