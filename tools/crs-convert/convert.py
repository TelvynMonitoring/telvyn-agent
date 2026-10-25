"""Converte as regras do OWASP Core Rule Set (SecRule) para o formato de regras do motor do WAF do Telvyn.

Uso: python -I convert.py <pasta do CRS> <saída.json> [--max-paranoia 2]

Só traduz formato: variáveis -> endereços, operadores, transformações e cadeias (chain). Regra que depende de algo
que o motor não tem (estado TX, pontuação de anomalia, validadores de protocolo) é pulada e listada no relatório.
O texto de cada regra (padrões, listas) vem do CRS, copyright dos colaboradores do OWASP CRS, licença Apache 2.0.
"""
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrules as sr

REQUEST_FILES = "REQUEST-9[1-4]*.conf"
EXCLUDED_TERMS = ("datadog",)

ADDRESSES = {
    "ARGS": ["server.request.query", "server.request.body", "server.request.path_params"],
    "ARGS_GET": ["server.request.query"],
    "ARGS_POST": ["server.request.body"],
    "REQUEST_COOKIES": ["server.request.cookies"],
    "REQUEST_HEADERS": ["server.request.headers.no_cookies"],
    "REQUEST_FILENAME": ["server.request.uri.raw"],
    "REQUEST_BASENAME": ["server.request.uri.raw"],
    "REQUEST_URI": ["server.request.uri.raw"],
    "REQUEST_URI_RAW": ["server.request.uri.raw"],
    "REQUEST_BODY": ["server.request.body"],
    "REQUEST_METHOD": ["server.request.method"],
    "XML": ["server.request.body"],
    "FILES": ["server.request.body.filenames"],
    "FILES_NAMES": ["server.request.body.filenames"],
}
KEYS_ONLY = {"ARGS_NAMES": "ARGS", "REQUEST_COOKIES_NAMES": "REQUEST_COOKIES", "REQUEST_HEADERS_NAMES": "REQUEST_HEADERS",
             "ARGS_GET_NAMES": "ARGS_GET", "ARGS_POST_NAMES": "ARGS_POST"}

TRANSFORMS = {
    "lowercase": "lowercase", "removeNulls": "removeNulls", "urlDecode": "urlDecode", "urlDecodeUni": "urlDecodeUni",
    "htmlEntityDecode": "htmlEntityDecode", "jsDecode": "jsDecode", "cssDecode": "cssDecode", "base64Decode": "base64Decode",
    "compressWhitespace": "compressWhitespace", "removeWhitespace": "removeWhitespace", "normalizePath": "normalizePath",
    "normalizePathWin": "normalizePathWin", "removeComments": "removeComments", "replaceComments": "replaceComments",
    "removeCommentsChar": "removeCommentsChar", "cmdLine": "cmdLine", "escapeSeqDecode": "escapeSeqDecode",
    "utf8toUnicode": "utf8toUnicode", "none": None,
}

TYPES = {
    "attack-sqli": "sql_injection", "attack-xss": "xss", "attack-rce": "command_injection", "attack-lfi": "lfi",
    "attack-rfi": "rfi", "attack-ssrf": "ssrf", "attack-injection-php": "php_code_injection",
    "attack-injection-java": "java_code_injection", "attack-injection-generic": "generic_injection",
    "attack-protocol": "http_protocol_violation", "attack-reputation-scanner": "security_scanner",
    "attack-fixation": "session_fixation", "attack-ssti": "template_injection", "attack-multipart-header": "http_protocol_violation",
    "attack-generic": "generic_injection",
}


class Skip(Exception):
    pass


def targets(variables):
    """Lista de (endereço, key_path, keys_only) das variáveis de uma regra; Skip se alguma não tem equivalente."""
    out = []
    for raw in variables.split("|"):
        if raw.startswith("!"):
            continue  # exclusão de alvo: o motor não tem; seguir sem ela deixa a regra mais ampla, nunca mais fraca
        name, _, selector = raw.partition(":")
        name = name.lstrip("&")
        if raw.startswith("&"):
            raise Skip("contagem de variável")
        if name in KEYS_ONLY:
            base, keys = KEYS_ONLY[name], True
        else:
            base, keys = name, False
        if base not in ADDRESSES:
            raise Skip("variável " + name)
        key_path = None
        if selector and not selector.startswith("/"):
            key_path = [selector.lower()] if base == "REQUEST_HEADERS" else [selector]
        # Seletor por regex (REQUEST_COOKIES:/x/, XML:/*): vale a variável inteira, que é mais ampla, nunca mais fraca.
        for address in ADDRESSES[base]:
            out.append((address, key_path, keys))
    if not out:
        raise Skip("sem alvo")
    return out


def data_file(root, name):
    path = os.path.join(root, "rules", name)
    if not os.path.isfile(path):
        raise Skip("lista " + name)
    with open(path, encoding="utf-8") as handle:
        entries = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    # Entradas que citam o nome de um fornecedor ficam de fora: o agent não pode carregar essa marca.
    return [entry for entry in entries if not any(term in entry.lower() for term in EXCLUDED_TERMS)]


def operator(text, root):
    """(nome do operador, parâmetros, negado) a partir de '[!]@op argumento'."""
    negated = text.startswith("!")
    body = text[1:] if negated else text
    if not body.startswith("@"):
        name, argument = "rx", body
    else:
        name, _, argument = body[1:].partition(" ")
    if "%{" in argument:
        raise Skip("argumento com macro do CRS")
    if name == "rx":
        return "match_regex", {"regex": argument, "options": {"case_sensitive": True, "min_length": 1}}, negated
    if name == "pm":
        return "phrase_match", {"list": argument.split()}, negated
    if name == "pmFromFile":
        return "phrase_match", {"list": data_file(root, argument)}, negated
    if name in ("contains", "streq", "beginsWith", "endsWith", "within"):
        escaped = re.escape(argument)
        pattern = {"contains": escaped, "streq": "^" + escaped + "$", "beginsWith": "^" + escaped,
                   "endsWith": escaped + "$", "within": None}[name]
        if pattern is None:
            return "phrase_match", {"list": argument.split(), "options": {"enforce_word_boundary": False}}, negated
        return "match_regex", {"regex": pattern, "options": {"case_sensitive": True, "min_length": 1}}, negated
    if name == "detectSQLi":
        return "is_sqli", {}, negated
    if name == "detectXSS":
        return "is_xss", {}, negated
    raise Skip("operador @" + name)


def transformers(link):
    chain = []
    for name in sr.action(link, "t"):
        if name not in TRANSFORMS:
            raise Skip("transformação " + name)
        if name == "none":
            chain = []
        else:
            chain.append(TRANSFORMS[name])
    return chain


def convert_rule(rule, root):
    head = rule[0]
    rule_id = sr.action(head, "id")
    if not rule_id:
        raise Skip("sem id")
    conditions, all_transforms = [], None
    for link in rule:
        for variable in link["variables"].split("|"):
            if variable.lstrip("!&").split(":")[0] in ("TX", "MATCHED_VARS", "MATCHED_VAR", "REQBODY_PROCESSOR", "MULTIPART_PART_HEADERS",
                                                       "REQUEST_PROTOCOL", "ARGS_COMBINED_SIZE", "FILES_COMBINED_SIZE", "REQBODY_ERROR"):
                raise Skip("depende de estado ou protocolo (" + variable.split(":")[0] + ")")
        name, parameters, negated = operator(link["operator"], root)
        chain = transformers(link)
        inputs = []
        for address, key_path, keys in targets(link["variables"]):
            item = {"address": address}
            if key_path:
                item["key_path"] = key_path
            if keys:
                item["transformers"] = [*chain, "keys_only"]
            inputs.append(item)
        if not any("transformers" in item for item in inputs):
            all_transforms = chain
        condition = {"operator": ("!" if negated else "") + name, "parameters": {**parameters, "inputs": inputs}}
        if any("transformers" in item for item in inputs):
            for item in inputs:
                item.setdefault("transformers", chain)
        conditions.append((condition, chain))
    tags = sr.action(head, "tag")
    type_name = next((TYPES[t] for t in tags if t in TYPES), "attack")
    msg = (sr.action(head, "msg") or [""])[0]
    out = {
        "id": "crs-" + rule_id[0],
        "name": msg,
        "tags": {"type": type_name, "category": "attack_attempt", "paranoia_level": str(sr.paranoia(rule)), "source": "owasp-crs"},
        "conditions": [c for c, _ in conditions],
        "transformers": conditions[0][1] if len(conditions) == 1 else [],
    }
    for cond, chain in conditions:
        if len(conditions) > 1:
            for item in cond["parameters"]["inputs"]:
                if "transformers" not in item and chain:
                    item["transformers"] = chain
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    root, output = sys.argv[1], sys.argv[2]
    max_paranoia = int(sys.argv[sys.argv.index("--max-paranoia") + 1]) if "--max-paranoia" in sys.argv else 2
    version = os.environ.get("CRS_VERSION", "unknown")
    converted, skipped = [], {}
    for path in sorted(glob.glob(os.path.join(root, "rules", REQUEST_FILES))):
        with open(path, encoding="utf-8") as handle:
            rules = sr.rules(handle.read())
        for rule in rules:
            head = rule[0]
            if not sr.action(head, "id"):
                continue
            if not any(k == "block" for k, _ in head["actions"]):
                continue  # as sem block são regras de controle do CRS (paranoia, exceções), não detecção
            if sr.paranoia(rule) > max_paranoia:
                skipped.setdefault("paranoia acima do limite", []).append(sr.action(head, "id")[0])
                continue
            try:
                converted.append(convert_rule(rule, root))
            except Skip as reason:
                skipped.setdefault(str(reason), []).append(sr.action(head, "id")[0])
    extras = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "api-schema.json"), encoding="utf-8"))
    document = {"version": "2.2", "metadata": {"rules_version": "crs-" + version}, "rules": converted, **extras}
    with open(output, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=1)
    print("regras convertidas:", len(converted))
    for reason, ids in sorted(skipped.items(), key=lambda kv: -len(kv[1])):
        print("  puladas (%d): %s" % (len(ids), reason))


if __name__ == "__main__":
    main()
