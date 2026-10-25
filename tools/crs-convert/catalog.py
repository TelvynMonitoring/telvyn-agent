"""Gera o catálogo de regras do backend (apm/waf-rules-catalog.json) a partir do waf-rules.json dos agents.

Uso: python -I catalog.py <waf-rules.json> <saída.json>
"""
import json
import sys


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    document = json.load(open(sys.argv[1], encoding="utf-8"))
    rules = [{"id": r["id"], "name": r["name"], "type": r["tags"]["type"], "category": r["tags"]["category"]} for r in document["rules"]]
    catalog = {"rules_version": "waf-" + document["metadata"]["rules_version"], "rules": rules}
    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as handle:
        json.dump(catalog, handle, ensure_ascii=False, indent=1)
    print(catalog["rules_version"], len(rules))


if __name__ == "__main__":
    main()
