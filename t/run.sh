#!/bin/sh
# jarv test suite.
#
# Nothing here is checked against jarv's own output. The authorities are
# listed in PLAN.md; the ones this file shells out to are named at the top of
# each section.
#
# The corpus is built here, at run time, into a mktemp directory, because it
# contains a keystore and a private key and neither of those belongs in a
# git object.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

pass=0
fail=0
ok()  { pass=$((pass+1)); printf 'ok   %s\n' "$*"; }
bad() { fail=$((fail+1)); printf 'FAIL %s\n' "$*"; }

[ -f "$root/build/jarv/Main.class" ] || { echo "no build; run make"; exit 2; }
newest=$(ls -t "$root"/src/jarv/*.java | head -1)
[ "$newest" -nt "$root/build/jarv/Main.class" ] && {
	echo "$newest is newer than the build; run make"; exit 2; }

for tool in jarsigner keytool jar openssl unzip zipinfo; do
	command -v "$tool" >/dev/null || {
		echo "$tool not found; it is an oracle, not a nicety"; exit 2; }
done

ok "toolchain present"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
