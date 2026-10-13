"""Package the published dependencies in the .NET shared-store layout."""
import json
import pathlib
import platform
import shutil
import sys

root = pathlib.Path(sys.argv[1])
deps_path = root / "Telvyn.Agent.deps.json"
deps = json.loads(deps_path.read_text())
architecture = {"x86_64": "x64", "aarch64": "arm64"}[platform.machine()]
store = root / "store" / architecture / "net8.0"
for libraries in deps["targets"].values():
    for name, assets in libraries.items():
        library = deps["libraries"][name]
        if library["type"] == "project":
            library.update(type="package", path=name.lower())
        for path in assets.get("runtime", {}):
            source = root / pathlib.Path(path).name
            target = store / library["path"] / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
deps_path.write_text(json.dumps(deps))
