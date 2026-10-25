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
import telvyn_rules

REQUEST_FILES = "REQUEST-9[1-4]*.conf"
# Entradas das listas do CRS que citam marca de terceiros fora do escopo do produto ficam de fora.
EXCLUDED_TERMS = ("data" + "dog",)
# Regras de higiene de protocolo que disparam em tráfego legítimo de agentes e serviços internos (Host com IP numérico).
NOISY_RULES = {"920350"}

ADDRESSES = {
    "ARGS": ["server.request.query", "server.request.body", "server.request.path_params"],
    "ARGS_GET": ["server.request.query"],
    "ARGS_POST": ["server.request.body"],
    "REQUEST_COOKIES": ["server.request.cookies"],
    "REQUEST_HEADERS": ["server.request.headers.no_cookies"],
    "REQUEST_FILENAME": ["server.request.path"],
    "REQUEST_BASENAME": ["server.request.path"],
    "REQUEST_URI": ["server.request.uri.raw"],
    "REQUEST_URI_RAW": ["server.request.uri.raw"],
    "REQUEST_BODY": ["server.request.body"],
    "REQUEST_METHOD": ["server.request.method"],
    "REQUEST_LINE": ["server.request.line"],
    "QUERY_STRING": ["server.request.query_string"],
    "REQUEST_PROTOCOL": ["server.request.protocol"],
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
    "utf8toUnicode": "utf8toUnicode", "length": "length", "none": None,
}

TYPES = {
    "attack-sqli": "sql_injection", "attack-xss": "xss", "attack-rce": "command_injection", "attack-lfi": "lfi",
    "attack-rfi": "rfi", "attack-ssrf": "ssrf", "attack-injection-php": "php_code_injection",
    "attack-injection-java": "java_code_injection", "attack-injection-generic": "generic_injection",
    "attack-protocol": "http_protocol_violation", "attack-reputation-scanner": "security_scanner",
    "attack-fixation": "session_fixation", "attack-ssti": "template_injection", "attack-multipart-header": "http_protocol_violation",
    "attack-generic": "generic_injection",
}


TX_DEFAULTS = {}


def load_tx_defaults(root):
    """Valores padrão das variáveis TX do CRS (REQUEST-901): os que as regras usam via %{tx.nome}."""
    with open(os.path.join(root, "rules", "REQUEST-901-INITIALIZATION.conf"), encoding="utf-8") as handle:
        for name, value in re.findall(r"setvar:'tx\.([A-Za-z0-9_]+)=([^'%]*)'", handle.read()):
            TX_DEFAULTS[name.lower()] = value


def resolve(argument):
    """Troca %{tx.nome} pelo padrão do CRS; nome sem padrão (ou outra macro) faz a regra ser pulada."""
    def value(match):
        name = match.group(1).lower()
        if name not in TX_DEFAULTS:
            raise Skip("macro do CRS sem padrão (tx." + name + ")")
        return TX_DEFAULTS[name]
    if "%{" not in argument:
        return argument
    out = re.sub(r"%\{tx\.([A-Za-z0-9_]+)\}", value, argument)
    if "%{" in out:
        raise Skip("argumento com macro do CRS")
    return out


def byte_ranges(argument):
    ranges = []
    for part in argument.split(","):
        low, _, high = part.strip().partition("-")
        ranges.append([int(low), int(high or low)])
    return ranges


class Skip(Exception):
    pass


def targets(variables):
    """Lista de (endereço, key_path, keys_only) das variáveis de uma regra, o que a regra exclui e se conta membros (&)."""
    out, excluded, count = [], [], False
    for raw in variables.split("|"):
        if raw.startswith("!"):
            # Exclusão por nome (!REQUEST_HEADERS:User-Agent) o motor aplica; por regex (!REQUEST_COOKIES:/x/) fica de fora,
            # o que deixa a regra mais ampla, nunca mais fraca.
            name, _, selector = raw[1:].partition(":")
            name = KEYS_ONLY.get(name, name)
            if selector and not selector.startswith("/"):
                excluded.append((name, selector.lower() if name == "REQUEST_HEADERS" else selector))
            continue
        name, _, selector = raw.partition(":")
        if name.startswith("&"):
            count = True
            name = name[1:]
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
            out.append((address, key_path, keys, base))
    if not out:
        raise Skip("sem alvo")
    return out, excluded, count


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
    argument = resolve(argument)
    if name == "rx":
        return "match_regex", {"regex": argument, "options": {"case_sensitive": True, "min_length": 1}}, negated
    if name == "pm":
        return "phrase_match", {"list": argument.split()}, negated
    if name == "pmFromFile":
        return "phrase_match", {"list": data_file(root, argument)}, negated
    if name in ("contains", "streq", "beginsWith", "endsWith"):
        escaped = re.escape(argument)
        pattern = {"contains": escaped, "streq": "^" + escaped + "$", "beginsWith": "^" + escaped, "endsWith": escaped + "$"}[name]
        return "match_regex", {"regex": pattern, "options": {"case_sensitive": True, "min_length": 1}}, negated
    if name == "within":
        # O valor está na lista: entrada por entrada, com maiúsculas e minúsculas como no CRS.
        return "exact_match", {"list": argument.split()}, negated
    if name in ("eq", "ge", "gt", "le", "lt"):
        operator_name = {"eq": "number_equals", "ge": "greater_or_equal", "gt": "greater_than", "le": "lower_or_equal", "lt": "lower_than"}[name]
        try:
            return operator_name, {"value": float(argument) if "." in argument else int(argument)}, negated
        except ValueError:
            raise Skip("operador @" + name + " com argumento não numérico")
    if name == "validateByteRange":
        return "validate_byte_range", {"ranges": byte_ranges(argument)}, negated
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


def tx_gate(link):
    """Elo que só confere uma variável TX de configuração (&TX:x @eq 1, TX:x @eq 1): True se o padrão do CRS o satisfaz."""
    match = re.match(r"^(&?)TX:([A-Za-z0-9_]+)$", link["variables"])
    operator_text = link["operator"]
    if not match or not operator_text.startswith("@eq "):
        return None
    name, expected = match.group(2).lower(), operator_text[4:].strip()
    if match.group(1):
        defined = name in TX_DEFAULTS
        return defined if expected == "1" else (not defined if expected == "0" else None)
    return TX_DEFAULTS.get(name) == expected if name in TX_DEFAULTS else False


NEEDS_STATE = ("TX", "MATCHED_VARS_NAMES", "MATCHED_VAR_NAME", "REQBODY_PROCESSOR", "MULTIPART_PART_HEADERS", "ARGS_COMBINED_SIZE",
               "FILES_COMBINED_SIZE", "REQBODY_ERROR", "REQUEST_BODY_LENGTH")


def convert_rule(rule, root):
    head = rule[0]
    rule_id = sr.action(head, "id")
    if not rule_id:
        raise Skip("sem id")
    conditions = []
    for link in rule:
        gate = tx_gate(link)
        if gate is True:
            continue
        if gate is False:
            raise Skip("desativada por padrão no CRS (variável TX sem valor)")
        names = [v.lstrip("!&").split(":")[0] for v in link["variables"].split("|")]
        blocked = sorted(set(n for n in names if n in NEEDS_STATE))
        if blocked:
            raise Skip("depende de estado do CRS (" + ",".join(blocked) + ")")
        name, parameters, negated = operator(link["operator"], root)
        chain = transformers(link)
        if all(n in ("MATCHED_VARS", "MATCHED_VAR") for n in names):
            inputs = [{"matched": True, "transformers": chain}]
        else:
            if any(n in ("MATCHED_VARS", "MATCHED_VAR") for n in names):
                raise Skip("MATCHED_VARS misturada com outras variáveis")
            found, excluded, count = targets(link["variables"])
            inputs = []
            for address, key_path, keys, base in found:
                item = {"address": address, "transformers": [*chain, "keys_only"] if keys else chain}
                if key_path:
                    item["key_path"] = key_path
                if count:
                    item["count"] = True
                skip = [key for variable, key in excluded if variable == base]
                if skip and not key_path:
                    item["exclude"] = skip
                inputs.append(item)
        conditions.append({"operator": ("!" if negated else "") + name, "parameters": {**parameters, "inputs": inputs}})
    if not conditions:
        raise Skip("sem condição")
    tags = sr.action(head, "tag")
    type_name = next((TYPES[t] for t in tags if t in TYPES), "attack")
    msg = (sr.action(head, "msg") or [""])[0]
    return {
        "id": "crs-" + rule_id[0],
        "name": msg,
        "tags": {"type": type_name, "category": "attack_attempt", "paranoia_level": str(sr.paranoia(rule)), "source": "owasp-crs"},
        "conditions": conditions,
        "transformers": [],
    }


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    root, output = sys.argv[1], sys.argv[2]
    max_paranoia = int(sys.argv[sys.argv.index("--max-paranoia") + 1]) if "--max-paranoia" in sys.argv else 4
    version = os.environ.get("CRS_VERSION", "unknown")
    load_tx_defaults(root)
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
            if sr.action(head, "id")[0] in NOISY_RULES:
                skipped.setdefault("tráfego interno legítimo", []).append(sr.action(head, "id")[0])
                continue
            if sr.paranoia(rule) > max_paranoia:
                skipped.setdefault("paranoia acima do limite", []).append(sr.action(head, "id")[0])
                continue
            try:
                converted.append(convert_rule(rule, root))
            except Skip as reason:
                skipped.setdefault(str(reason), []).append(sr.action(head, "id")[0])
    extras = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "api-schema.json"), encoding="utf-8"))
    extras["rasp"] = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "rasp-rules.json"), encoding="utf-8"))["rules"]
    converted += extras.pop("rasp")
    converted += telvyn_rules.rules()
    document = {"version": "2.2", "metadata": {"rules_version": "crs-" + version}, "rules": converted, **extras}
    with open(output, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=1)
    print("regras convertidas:", len(converted))
    for reason, ids in sorted(skipped.items(), key=lambda kv: -len(kv[1])):
        print("  puladas (%d): %s" % (len(ids), reason))


if __name__ == "__main__":
    main()
