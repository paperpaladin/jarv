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

# ------------------------------------------------------------- build the corpus
"$here/corpus.sh" "$work" >/dev/null || { echo "corpus build failed"; exit 2; }
jars=$(ls "$work"/*.jar | sort)
njars=$(printf '%s\n' "$jars" | wc -l)
echo "--- corpus: $njars jars in $work"
[ "$njars" -ge 16 ] || { echo "corpus of $njars jars is too small"; exit 2; }

# ------------------------------- oracle: Info-ZIP zipinfo -v and unzip -l
echo "--- oracle: zipinfo -v, unzip -l (Info-ZIP, no JDK code)"
out=$(python3 "$here/zipcmp.py" "$root/jarv" $jars)
printf '%s\n' "$out" | grep -v '^ZIPCMP_' | grep '^FAIL' || true
p=$(printf '%s\n' "$out" | sed -n 's/^ZIPCMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^ZIPCMP_FAIL //p')
[ -n "$p" ] || { echo "zipcmp.py produced no count"; exit 2; }
echo "ok   container: $p facts agree with Info-ZIP, $f disagree"
pass=$((pass + p))
fail=$((fail + f))

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
