"""Transforma os testes de regressão do CRS (YAML, formato go-ftw) em um corpus JSON para medir a cobertura do motor.

Uso: PYTHONPATH=<pyyaml> python corpus.py <pasta do CRS> <saída.json>
Cada caso: id da regra testada, requisição (método, uri, cabeçalhos, corpo) e se a regra deve ou não ser disparada.
O corpus é dado de teste do CRS e fica fora do repositório (tamanho e conteúdo): o teste Java o lê pelo caminho
indicado em -Dtelvyn.waf.corpus.
"""
import glob
import json
import os
import sys

import yaml


def main():
    root, output = sys.argv[1], sys.argv[2]
    cases = []
    for path in sorted(glob.glob(os.path.join(root, "tests", "regression", "tests", "REQUEST-9[1-4]*", "*.yaml"))):
        try:
            with open(path, encoding="utf-8") as handle:
                document = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            print("ignorado:", path)
            continue
        for test in document.get("tests", []):
            for stage in test.get("stages", []):
                request = stage.get("input", {})
                log = (stage.get("output") or {}).get("log") or {}
                expect = [str(i) for i in (log.get("expect_ids") or [])]
                forbid = [str(i) for i in (log.get("no_expect_ids") or [])]
                if not expect and not forbid:
                    continue
                body = request.get("data")
                if body is None and request.get("encoded_request"):
                    continue
                cases.append({
                    "file": os.path.basename(os.path.dirname(path)) + "/" + os.path.basename(path),
                    "test": "%s-%s" % (document.get("rule_id"), test.get("test_id")),
                    "method": request.get("method", "GET"),
                    "uri": request.get("uri", "/"),
                    "headers": {str(k): str(v) for k, v in (request.get("headers") or {}).items()},
                    "body": body if isinstance(body, str) else None,
                    "expect": expect,
                    "forbid": forbid,
                })
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(cases, handle, ensure_ascii=False)
    print("casos:", len(cases))


if __name__ == "__main__":
    main()
