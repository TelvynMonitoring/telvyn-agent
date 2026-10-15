import re
from urllib.parse import urlsplit, urlunsplit


def sql_mask(statement):
    if not isinstance(statement, str) or len(statement) > 32768:
        return "[statement omitted]"
    output, index = [], 0
    while index < len(statement):
        char = statement[index]
        if statement.startswith("--", index) or char == "#":
            end = statement.find("\n", index)
            index = len(statement) if end < 0 else end
            output.append(" ")
        elif statement.startswith("/*", index):
            depth, index = 1, index + 2
            while index < len(statement) and depth:
                if statement.startswith("/*", index):
                    depth, index = depth + 1, index + 2
                elif statement.startswith("*/", index):
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
            output.append(" ")
        elif char == "'":
            index += 1
            while index < len(statement):
                if statement[index] == "\\":
                    index += 2
                elif statement[index] == "'":
                    index += 1
                    if index < len(statement) and statement[index] == "'":
                        index += 1
                    else:
                        break
                else:
                    index += 1
            output.append("?")
        elif char in ('"', '`'):
            start, index = index, index + 1
            closed = False
            while index < len(statement):
                if char == '"' and statement[index] == "\\":
                    index += 2
                elif statement[index] == char:
                    index += 1
                    if index < len(statement) and statement[index] == char:
                        index += 1
                    else:
                        closed = True
                        break
                else:
                    index += 1
            # Double quotes can be string literals in MySQL/SQLite; mask conservatively.
            output.append(statement[start:index] if closed and char == '`' else "?")
        elif char == "$" and (match := re.match(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$", statement[index:])):
            delimiter = match.group()
            end = statement.find(delimiter, index + len(delimiter))
            index = len(statement) if end < 0 else end + len(delimiter)
            output.append("?")
        elif char == "$" and (match := re.match(r"\$[0-9]+", statement[index:])):
            output.append(match.group())
            index += len(match.group())
        elif char == "%" and (match := re.match(r"%(?:\([A-Za-z_][A-Za-z_0-9]*\))?s", statement[index:])):
            output.append(match.group())
            index += len(match.group())
        elif (char.isdigit() or char == "." and index + 1 < len(statement) and statement[index + 1].isdigit()) and (
                index == 0 or not (statement[index - 1].isalnum() or statement[index - 1] in "_$:")):
            match = re.match(r"(?:0[xX][0-9a-fA-F]+|0[bB][01]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)", statement[index:])
            if match:
                output.append("?")
                index += len(match.group())
            else:
                index += 1
        else:
            output.append(char)
            index += 1
    return re.sub(r"\s+", " ", "".join(output)).strip()


def clean_url(value):
    value = value.split("?", 1)[0].split("#", 1)[0]
    try:
        parts = urlsplit(value)
        if parts.netloc and "@" in parts.netloc:
            return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[1], parts.path, "", ""))
    except ValueError:
        return "[invalid URL]"
    return value


def clean_attributes(values):
    result = {}
    for key, value in (values or {}).items():
        normalized = key.lower().replace("-", "_")
        if normalized in ("url.query", "http.query", "http.query_string"):
            continue
        if normalized.startswith(("db.statement.parameters", "db.query.parameter", "db.parameters")):
            continue
        if normalized.startswith(("http.request.body", "http.response.body")) and not normalized.endswith(".size"):
            continue
        if normalized.startswith(("http.request.header", "http.response.header")):
            continue
        if "header" in normalized and any(part in normalized for part in ("authorization", "cookie", "token", "api_key", "secret", "password")):
            continue
        if normalized in ("http.cookie", "http.cookies", "http.request.cookies", "http.response.cookies"):
            continue
        if key in ("http.url", "http.target", "url.full") and isinstance(value, str):
            value = clean_url(value)
        if key in ("db.statement", "db.query.text"):
            value = sql_mask(value)
        result[key] = value
    for current, legacy in (("db.system.name", "db.system"), ("db.query.text", "db.statement"), ("db.namespace", "db.name")):
        if current in result:
            result.setdefault(legacy, result[current])
    return result
