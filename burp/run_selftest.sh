#!/bin/sh
# Offline self-test: runs the extension inside the bundled Jython with a mock
# Burp API. Needs only Java 8+. No internet required.
cd "$(dirname "$0")"
OUT="${TMPDIR:-/tmp}/js_recon_selftest"; mkdir -p "$OUT"
echo "== Extension load / capture / UI / export tests =="
java -Djava.awt.headless=true -jar jython-standalone-2.7.4.jar selftest/harness.py . selftest/mock selftest/fixture-vulnerable.js "$OUT" 2>&1 | grep -E "^\[(OK|FAIL)\]|took|flagged"
echo "== Detection edge cases =="
java -jar jython-standalone-2.7.4.jar selftest/edge_cases.py . selftest/mock 2>&1
