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
# JARV_CORPUS reuses a corpus built by an earlier run. It exists because
# building one costs four keytool invocations and about half a minute, and
# the mutation harness runs the suite dozens of times. It is opt-in by an
# environment variable rather than a fixed path, so two concurrent ordinary
# runs still cannot feed each other their jars.
if [ -n "${JARV_CORPUS:-}" ]; then
	work=$JARV_CORPUS
	keep=1
else
	work=$(mktemp -d)
	keep=0
fi
cleanup() { [ "$keep" = 0 ] && rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

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
if [ ! -f "$work/good-rsa.jar" ]; then
	"$here/corpus.sh" "$work" >/dev/null || { echo "corpus build failed"; exit 2; }
fi
jars=$(ls "$work"/*.jar | sort)
njars=$(printf '%s\n' "$jars" | wc -l)
echo "--- corpus: $njars jars in $work"
[ "$njars" -ge 16 ] || { echo "corpus of $njars jars is too small"; exit 2; }

# ------------------------------------------------- what the corpus contains
# Counted with python3's zipfile and a raw byte scan, not with jarv, so that
# a construct jarv cannot see reads as zero here and turns the suite red.
if python3 "$here/constructs.py" $jars > "$work/constructs.txt"; then
	ok "every required construct is present in the corpus"
else
	bad "corpus is missing a construct: $(grep '^MISSING' "$work/constructs.txt")"
fi
sed -n 's/^construct /     /p' "$work/constructs.txt"

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

# ---------------- oracle: coreutils digests, coreutils base64, jarsigner's
# ---------------- own numbers in the .SF for the manifest byte ranges
echo "--- oracle: coreutils sha*sum and base64, and jarsigner's .SF values"
clean=""
for j in good-rsa good-ec good-sha512 expired two-signers zip64 zip64-store \
		zip64-dd stored nodd comment added; do
	clean="$clean $work/$j.jar"
done
out=$(python3 "$here/mfcmp.py" "$root/jarv" clean $clean)
printf '%s\n' "$out" | grep '^FAIL' || true
p=$(printf '%s\n' "$out" | sed -n 's/^MFCMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^MFCMP_FAIL //p')
[ -n "$p" ] || { echo "mfcmp.py produced no count"; exit 2; }
echo "ok   manifest: $p facts agree, $f disagree"
pass=$((pass + p))
fail=$((fail + f))

# A tampered entry must show up as exactly one digest mismatch, and the
# archive with an entry dropped as none, because dropping an entry does not
# change any digest in the manifest. Both numbers are asserted so that a
# verifier which found mismatches everywhere, or nowhere, is caught.
for pair in tampered:1 bitflip:1 dropped:0 unsigned:0; do
	j=${pair%%:*}
	want=${pair##*:}
	out=$(python3 "$here/mfcmp.py" "$root/jarv" dirty "$work/$j.jar")
	got=$(printf '%s\n' "$out" | sed -n 's/^MFCMP_MISMATCH //p')
	nf=$(printf '%s\n' "$out" | sed -n 's/^MFCMP_FAIL //p')
	if [ "$got" = "$want" ] && [ "$nf" = 0 ]; then
		ok "$j.jar: $got manifest digest mismatches, as expected"
	else
		bad "$j.jar: $got manifest digest mismatches, expected $want ($nf errors)"
	fi
done

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
