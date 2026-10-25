"""Leitor mínimo de SecRule (linguagem do ModSecurity/CRS): diretivas, variáveis, operador e ações."""
import re


def directives(text):
    """Junta continuações de linha e devolve as diretivas como listas de tokens."""
    text = text.replace("\\\r\n", " ").replace("\\\n", " ")
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(tokenize(line))
    return out


def tokenize(line):
    tokens, i, n = [], 0, len(line)
    while i < n:
        if line[i].isspace():
            i += 1
            continue
        if line[i] == '"':
            j, buf = i + 1, []
            while j < n and line[j] != '"':
                if line[j] == "\\" and j + 1 < n and line[j + 1] == '"':
                    buf.append('"')
                    j += 2
                    continue
                buf.append(line[j])
                j += 1
            tokens.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and not line[j].isspace():
                j += 1
            tokens.append(line[i:j])
            i = j
    return tokens


def split_actions(actions):
    """Ações separadas por vírgula, respeitando aspas simples."""
    out, buf, quoted = [], [], False
    for ch in actions:
        if ch == "'":
            quoted = not quoted
        if ch == "," and not quoted:
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    parsed = []
    for item in out:
        if not item:
            continue
        key, _, value = item.partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1]
        parsed.append((key.strip(), value))
    return parsed


def rules(text):
    """SecRule com suas cadeias (chain): lista de regras, cada uma uma lista de elos."""
    result, current = [], None
    for tokens in directives(text):
        if not tokens or tokens[0] != "SecRule" or len(tokens) < 3:
            continue
        variables, operator = tokens[1], tokens[2]
        actions = split_actions(tokens[3]) if len(tokens) > 3 else []
        link = {"variables": variables, "operator": operator, "actions": actions}
        if current is None:
            current = [link]
        else:
            current.append(link)
        if not any(k == "chain" for k, _ in actions):
            result.append(current)
            current = None
    return result


def action(link, name):
    return [v for k, v in link["actions"] if k == name]


def paranoia(rule):
    for tag in action(rule[0], "tag"):
        m = re.match(r"paranoia-level/(\d)", tag)
        if m:
            return int(m.group(1))
    return 1
