"""Regras de detecção próprias do Telvyn, escritas aqui (não vêm do CRS): categorias que o CRS não cobre ou cobre pouco,
como exploração de cloud metadata, SSRF, Log4Shell, poluição de protótipo e tentativas de achar arquivos que não existem.

Cada regra segue o formato do motor (ver Engine/waf.cjs). O convert.py junta estas regras às do CRS.
"""

VALUES = ["server.request.query", "server.request.body", "server.request.path_params", "server.request.cookies"]
VALUES_AND_HEADERS = VALUES + ["server.request.headers.no_cookies"]
PATH = ["server.request.path"]
DECODE = ["urlDecodeUni", "htmlEntityDecode"]


def inputs(addresses, transformers=(), keys=False):
    out = []
    for address in addresses:
        out.append({"address": address, "transformers": list(transformers)})
        if keys:
            out.append({"address": address, "transformers": [*transformers, "keys_only"]})
    return out


def regex(pattern, addresses, transformers=DECODE, keys=False, case_sensitive=False):
    return {"operator": "match_regex", "parameters": {"regex": pattern, "options": {"case_sensitive": case_sensitive, "min_length": 3},
                                                      "inputs": inputs(addresses, transformers, keys)}}


def phrases(words, addresses, transformers=("lowercase", *DECODE)):
    return {"operator": "phrase_match", "parameters": {"list": words, "options": {"enforce_word_boundary": False},
                                                       "inputs": inputs(addresses, transformers)}}


def status(pattern):
    return {"operator": "match_regex", "parameters": {"regex": pattern, "options": {"case_sensitive": True, "min_length": 3},
                                                      "inputs": [{"address": "server.response.status", "transformers": []}]}}


def rule(rule_id, name, type_, conditions, category="attack_attempt", level=1):
    return {"id": rule_id, "name": name, "tags": {"type": type_, "category": category, "paranoia_level": str(level), "source": "telvyn"},
            "conditions": conditions, "transformers": []}


OOB_DOMAINS = ["burpcollaborator.net", "oastify.com", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
               "interact.sh", "interactsh.com", "requestbin.net", "requestbin.com", "hookbin.com", "webhook.site", "pipedream.net",
               "dnslog.cn", "dnslog.link", "ceye.io", "canarytokens.com", "bxss.me", "xsshunter.com", "xss.ht", "mockbin.org",
               "beeceptor.com", "requestcatcher.com", "ssrf.cc", "dnsbin.zhack.ca", "pingb.in"]
SCANNER_AGENTS = ["nuclei", "projectdiscovery", "zgrab", "masscan", "gobuster", "feroxbuster", "ffuf", "wfuzz", "dirbuster",
                  "nikto", "sqlmap", "acunetix", "netsparker", "nessus", "openvas", "w3af", "arachni", "skipfish", "wapiti", "burpsuite",
                  "zaproxy", "owasp zap", "metasploit", "hydra", "havij", "nmap scripting engine", "whatweb", "jaeles", "dalfox", "commix"]

SENSITIVE_404 = r"(?:/\.(?:env|git|svn|hg|htpasswd|htaccess|ssh|aws|npmrc|DS_Store|bash_history)|id_rsa|wp-config|/config\.(?:php|json|yml|yaml|ini)|\.(?:pem|key|pfx|p12|sql|sqlite3?|db)$)"
INTERNAL_URL = (r"(?:https?|gopher|dict|ftp|ldaps?|tftp)://(?:[^/@\s]*@)?(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[(?:::1?|::ffff:[0-9a-f.:]+)\]|"
                r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})(?:[:/?#]|$)")


def rules():
    return [
        # Ferramentas e domínios de interação fora de banda
        rule("tlv-913-001", "Domínio de interação fora de banda (OAST) usado por ferramentas de teste de invasão", "security_scanner",
             [phrases(OOB_DOMAINS, VALUES_AND_HEADERS)]),
        rule("tlv-913-002", "User-Agent de ferramenta de varredura ou fuzzing", "security_scanner",
             [{"operator": "phrase_match", "parameters": {"list": SCANNER_AGENTS, "options": {"enforce_word_boundary": False},
                                                          "inputs": [{"address": "server.request.headers.no_cookies", "key_path": ["user-agent"], "transformers": ["lowercase"]}]}}]),
        # Injeção em bancos e linguagens de expressão
        rule("tlv-000-001", "Injeção em CQL (Cassandra)", "nosql_injection",
             [regex(r"\bALLOW\s+FILTERING\b|\bsystem(?:_schema|_auth|_distributed)?\.(?:local|peers|keyspaces|tables|columns|roles)\b|\bUSING\s+TTL\s+\d+|\bBATCH\s+.{0,80}\bAPPLY\s+BATCH\b", VALUES)]),
        rule("tlv-000-002", "Injeção de expressão OGNL", "java_code_injection",
             [regex(r"#_?memberAccess|#context\s*\[|@java\.lang\.(?:Runtime|ProcessBuilder|System)@|%\{\s*\(?\s*#|\bognl\.[A-Za-z]+\.|\(\s*#[A-Za-z_]+\s*=", VALUES_AND_HEADERS)]),
        rule("tlv-000-003", "Exploração do Spring4Shell (acesso ao classLoader por parâmetro)", "exploit_detection",
             [regex(r"\bclass\s*(?:\.|\[\s*['\"]?)\s*(?:module\s*(?:\.|\[\s*['\"]?)\s*)?classLoader\b", VALUES + ["server.request.headers.no_cookies"], keys=True)]),
        rule("tlv-000-004", "Poluição de protótipo em JavaScript (__proto__)", "js_code_injection",
             [regex(r"(?:^|[.\[\]'\"])__proto__(?:$|[.\[\]'\"=:])", VALUES, keys=True, transformers=("urlDecodeUni",))]),
        rule("tlv-000-005", "Poluição de protótipo em JavaScript (constructor.prototype)", "js_code_injection",
             [regex(r"constructor\s*(?:\.|\[\s*['\"]?|\]\s*\[\s*['\"]?)\s*prototype\b", VALUES, keys=True, transformers=("urlDecodeUni",))]),
        rule("tlv-000-006", "Injeção de template no lado do servidor (Velocity e Freemarker)", "java_code_injection",
             [regex(r"#set\s*\(\s*\$|<#assign\s|<#list\s|freemarker\.template\.utility\.(?:Execute|ObjectConstructor)|\$\{\s*['\"]freemarker|\$class\.(?:inspect|forName)|\.getClass\(\)\.forName\(|#foreach\s*\(\s*\$", VALUES)]),
        # Autenticação e arquivos enviados
        rule("tlv-920-001", "JWT sem assinatura (alg none)", "http_protocol_violation",
             [regex(r"^\s*Bearer\s+eyJhbGciOiJ(?:ub25l|Ob25l|OT05F|ub05F|NT05F)", ["server.request.headers.no_cookies"], transformers=(), case_sensitive=True)]),
        rule("tlv-920-100", "Envio de arquivo com extensão dupla", "unrestricted_file_upload",
             [regex(r"\.(?:php\d?|phtml|jspx?|aspx?|war|sh|py|pl|cgi)\.(?:jpe?g|png|gif|txt|pdf|bmp|ico)$|\.(?:jpe?g|png|gif|pdf|txt)\.(?:php\d?|phtml|jspx?|aspx?|war|sh)$", ["server.request.body.filenames"], transformers=("lowercase",))]),
        rule("tlv-920-110", "Arquivo compactado com caminho fora do diretório (Zip Slip)", "lfi",
             [regex(r"(?:^|[\\/])\.\.(?:[\\/]|$)", ["server.request.body.filenames"], transformers=("urlDecodeUni",))]),
        # Inclusão remota, comandos e XXE
        rule("tlv-931-001", "Inclusão remota de arquivo a partir de hospedagem de scripts públicos", "rfi",
             [regex(r"(?:https?|ftp)://[^/\s]*(?:pastebin\.com/raw|raw\.githubusercontent\.com|gist\.githubusercontent\.com|transfer\.sh|ix\.io|paste\.ee|hastebin\.com/raw)[^\s]*\.(?:txt|php|jsp|sh|py|pl|asp)", VALUES)]),
        rule("tlv-932-100", "Comando de rede executado por shell (baixar e executar ou shell reverso)", "command_injection",
             [regex(r"\b(?:curl|wget|fetch|tftp|ftp|nc|ncat|netcat|socat)\b[^\n]{0,120}(?:https?://|ftp://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\s-e\s)|\|\s*(?:ba|z|da|k)?sh\b|/dev/tcp/\d", VALUES)]),
        rule("tlv-932-110", "Injeção de comando por subprocesso de Python", "command_injection",
             [regex(r"__import__\s*\(\s*['\"]os['\"]\s*\)|\bsubprocess\.(?:Popen|call|run|check_output|getoutput)\s*\(|\bos\.(?:system|popen|exec[lv]p?e?)\s*\(", VALUES)]),
        rule("tlv-934-001", "XXE: entidade externa em documento XML", "xxe",
             [regex(r"<!ENTITY\s+(?:%\s+)?[^\s>]+\s+(?:SYSTEM|PUBLIC)\s|<!DOCTYPE[^>]{0,200}\[[^\]]{0,400}SYSTEM\s+['\"]", ["server.request.body"], transformers=())]),
        # SSRF e acesso a serviços internos
        rule("tlv-000-101", "SSRF: acesso ao serviço de metadados de nuvem", "ssrf",
             [regex(r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|169\.254\.170\.2\b|metadata\.azure\.com|/latest/meta-data|/computeMetadata/v1|/metadata/instance\?api-version", VALUES)]),
        rule("tlv-000-102", "Injeção de código JavaScript no servidor (módulos do sistema)", "js_code_injection",
             [regex(r"require\s*\(\s*['\"](?:child_process|fs|os|vm|net|cluster)['\"]\s*\)|process\.mainModule|process\.binding\s*\(|global\.process\b", VALUES)]),
        rule("tlv-000-103", "Leitura de arquivo .ini do Windows", "command_injection",
             [regex(r"(?:^|[\\/])(?:windows|winnt)[\\/](?:win|system)\.ini\b|\bboot\.ini\b", VALUES)]),
        rule("tlv-000-104", "Leitura de arquivos de contas do Linux", "command_injection",
             [regex(r"/etc/(?:passwd|shadow|group|sudoers)\b|/proc/self/(?:environ|cmdline)", VALUES)]),
        rule("tlv-000-105", "Atraso proposital em shell do Windows", "command_injection",
             [regex(r"\btimeout(?:\.exe)?\s+/t\s+\d+|\bping\s+-n\s+\d+\s+127\.0\.0\.1|\bwaitfor\s+/t\s+\d+", VALUES)]),
        rule("tlv-000-106", "SSRF: serviço OMI interno (CVE-2021-38647)", "ssrf",
             [regex(r"ExecuteShellCommand|OMI_Execute|/wsman\b", VALUES + ["server.request.body"], transformers=())]),
        rule("tlv-000-107", "SSRF: URL que aponta para serviço interno", "ssrf", [regex(INTERNAL_URL, VALUES)]),
        rule("tlv-000-108", "SSRF: endereço IP escondido em formato octal, hexadecimal, decimal ou IPv6",  "ssrf",
             [regex(r"https?://(?:[^/@\s]*@)?(?:0x[0-9a-f]{1,8}(?:[./:]|$)|0[0-7]{2,}\.|\d{8,10}(?:[/:?#]|$)|\[[0-9a-f:.]{2,}\])", VALUES)]),
        rule("tlv-000-109", "SSRF: domínio que redireciona para endereço interno", "ssrf",
             [regex(r"https?://[^/\s]*(?:\.nip\.io|\.sslip\.io|\.xip\.io|localtest\.me|lvh\.me|\.traefik\.me|\.vcap\.me)(?:[:/?#]|$)|://[^/@\s]+@(?:localhost|127\.|10\.|192\.168\.)", VALUES)]),
        rule("tlv-000-110", "SSRF: protocolo que não é HTTP", "ssrf",
             [regex(r"^\s*(?:gopher|dict|ldaps?|tftp|sftp|jar|netdoc|file|php|phar|expect|ogg|zip)://", VALUES, transformers=("urlDecodeUni",))]),
        rule("tlv-000-111", "Exploração do Log4Shell (CVE-2021-44228)", "exploit_detection",
             [regex(r"\$\{[^}]{0,50}j[^}]{0,20}n[^}]{0,20}d[^}]{0,20}i[^}]{0,20}:|\$\{(?:jndi|lower|upper|env|sys|java|date):[^}]{0,60}\$\{", VALUES_AND_HEADERS, keys=True)]),
        # Varredura: pedidos de arquivos e páginas que não existem (precisam do status da resposta)
        rule("tlv-000-201", "Varredura: busca de diretórios comuns que não existem", "security_scanner",
             [status(r"^404$"), regex(r"/(?:admin|administrator|backup|backups|old|test|dev|tmp|private|secret|phpmyadmin|cgi-bin|manager|console|wp-admin)/?$", PATH, transformers=("lowercase",))]),
        rule("tlv-000-202", "Varredura: busca de arquivos de documentação (readme, changelog)", "security_scanner",
             [status(r"^404$"), regex(r"/(?:readme|changelog|license|install|todo|release-notes?|version)(?:\.(?:md|txt|html?))?$", PATH, transformers=("lowercase",))]),
        rule("tlv-000-203", "Varredura: busca de recursos de Java EE que não existem", "security_scanner",
             [status(r"^404$"), regex(r"/(?:WEB-INF|META-INF)/|/web\.xml$|\.(?:jspx?|do|action|jsf)$|/struts[^/]*\.xml$", PATH, transformers=())]),
        rule("tlv-000-204", "Varredura: busca de arquivos de código que não existem", "security_scanner",
             [status(r"^404$"), regex(r"\.(?:php\d?|py|rb|pl|java|cs|go|ts|inc|class)(?:~|\.bak|\.old|\.orig|\.save|\.swp)?$", PATH, transformers=("lowercase",))]),
        rule("tlv-000-205", "Varredura: busca de pacotes de código-fonte que não existem", "security_scanner",
             [status(r"^404$"), regex(r"(?:src|source|sources|code|repo|project|app|site|www|web)[^/]*\.(?:zip|tar|tar\.gz|tgz|rar|7z)$", PATH, transformers=("lowercase",))]),
        rule("tlv-000-206", "Varredura: busca de arquivos sensíveis que não existem", "security_scanner",
             [status(r"^404$"), regex(SENSITIVE_404, PATH, transformers=("lowercase",))]),
        rule("tlv-000-207", "Varredura: busca de cópias de segurança que não existem", "security_scanner",
             [status(r"^404$"), regex(r"(?:backup|bak|dump|database|db|site|www|archive)[^/]*\.(?:zip|tar|gz|tgz|bz2|7z|rar|sql)$", PATH, transformers=("lowercase",))]),
        rule("tlv-000-208", "Varredura: entrada com caracteres de ataque que derruba a aplicação (erro 5xx)", "security_scanner",
             [status(r"^5\d\d$"), regex(r"['\"<>`]|%00|\.\./|\$\{", ["server.request.query_string"], transformers=("urlDecodeUni",))]),
        rule("tlv-000-209", "Varredura: busca de páginas que revelam a estrutura da aplicação", "security_scanner",
             [status(r"^404$"), regex(r"/(?:phpinfo(?:\.php)?|server-status|server-info|actuator(?:/[a-z]+)?|elmah\.axd|trace\.axd|debug|_profiler|telescope|jolokia|heapdump)/?$", PATH, transformers=("lowercase",))]),
        rule("tlv-000-210", "Varredura: busca de documentação de API que não existe", "security_scanner",
             [status(r"^404$"), regex(r"/(?:swagger(?:-ui)?(?:\.json|\.yaml|/index\.html)?|openapi\.(?:json|yaml)|api-docs|v[23]/api-docs|redoc|graphql/schema|docs)/?$", PATH, transformers=("lowercase",))]),
    ]
