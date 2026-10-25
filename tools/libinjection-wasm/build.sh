#!/usr/bin/env sh
# Compila o libinjection (sem modificação) para WebAssembly: telvyn-java-agent/src/main/wasm/libinjection.wasm.
# Uso: WASI_SDK=/caminho/do/wasi-sdk LIBINJECTION=/caminho/do/libinjection tools/libinjection-wasm/build.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src="$LIBINJECTION/src"
out="$here/../../telvyn-java-agent/src/main/wasm/libinjection.wasm"
"$WASI_SDK/bin/clang" --target=wasm32-wasip1 --sysroot="$WASI_SDK/share/wasi-sysroot" -O2 -DNDEBUG \
  -mexec-model=reactor -Wl,--no-entry -Wl,--strip-all \
  -I"$src" "$here/shim.c" "$src/libinjection_sqli.c" "$src/libinjection_xss.c" "$src/libinjection_html5.c" -o "$out"
echo "$out"
