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
[ "$njars" -ge 25 ] || { echo "corpus of $njars jars is too small"; exit 2; }

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

# -------------- oracle: coreutils base64 -d, and java.util.Base64 as a
# -------------- second opinion, over a sweep of the padded-group alphabet
javac -d "$work/probe" "$here/B64Probe.java" 2>/dev/null \
	&& probe="$work/probe" || probe=""
out=$(python3 "$here/b64cmp.py" "$root/jarv" $probe)
printf '%s\n' "$out" | grep -E '^(FAIL|ok)' || true
p=$(printf '%s\n' "$out" | sed -n 's/^B64CMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^B64CMP_FAIL //p')
[ -n "$p" ] || { echo "b64cmp.py produced no count"; exit 2; }
pass=$((pass + p))
fail=$((fail + f))

# ---------------- oracle: coreutils digests, coreutils base64, jarsigner's
# ---------------- own numbers in the .SF for the manifest byte ranges
echo "--- oracle: coreutils sha*sum and base64, and jarsigner's .SF values"
clean=""
for j in good-rsa good-ec good-sha512 expired two-signers zip64 zip64-store \
		zip64-dd zip64-partial stored nodd comment added; do
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

# --------------------------------- oracle: openssl asn1parse, node by node
echo "--- oracle: openssl asn1parse over every signature block"
mkdir -p "$work/der"
out=$(python3 "$here/dercmp.py" "$root/jarv" "$work/der" $jars)
printf '%s\n' "$out" | grep '^FAIL' || true
p=$(printf '%s\n' "$out" | sed -n 's/^DERCMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^DERCMP_FAIL //p')
[ -n "$p" ] || { echo "dercmp.py produced no count"; exit 2; }
echo "ok   DER: $p node facts agree with openssl asn1parse, $f disagree"
pass=$((pass + p))
fail=$((fail + f))

out=$(python3 "$here/dercases.py" "$root/jarv" "$work/der")
printf '%s\n' "$out" | grep -E '^(FAIL|ok)' || true
p=$(printf '%s\n' "$out" | sed -n 's/^DERCASE_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^DERCASE_FAIL //p')
[ -n "$p" ] || { echo "dercases.py produced no count"; exit 2; }
pass=$((pass + p))
fail=$((fail + f))

# ------------------- oracle: openssl pkcs7 -print, and keytool -printcert
echo "--- oracle: openssl pkcs7 -print, keytool -printcert -jarfile"
out=$(python3 "$here/p7cmp.py" "$root/jarv" "$work/der" $jars)
printf '%s\n' "$out" | grep -E '^(FAIL|refused)' || true
p=$(printf '%s\n' "$out" | sed -n 's/^P7CMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^P7CMP_FAIL //p')
r=$(printf '%s\n' "$out" | sed -n 's/^P7CMP_REFUSED //p')
[ -n "$p" ] || { echo "p7cmp.py produced no count"; exit 2; }
echo "ok   PKCS7: $p facts agree with openssl and keytool, $f disagree," \
	"$r refused by the oracle"
pass=$((pass + p))
fail=$((fail + f))

# ------------------------------- oracle: openssl ecparam, for the curves
out=$(python3 "$here/curvecmp.py" "$root/jarv")
printf '%s\n' "$out" | grep '^FAIL' || true
p=$(printf '%s\n' "$out" | sed -n 's/^CURVECMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^CURVECMP_FAIL //p')
[ -n "$p" ] || { echo "curvecmp.py produced no count"; exit 2; }
echo "ok   curves: $p constants agree with openssl ecparam, $f disagree"
pass=$((pass + p))
fail=$((fail + f))

# ---------- oracle: openssl pkeyutl -verifyrecover and openssl dgst -verify
echo "--- oracle: openssl pkeyutl -verifyrecover, openssl dgst -verify"
mkdir -p "$work/sig"
out=$(python3 "$here/sigcmp.py" "$root/jarv" "$work/sig" $jars)
printf '%s\n' "$out" | grep -E '^(FAIL|refused)' || true
p=$(printf '%s\n' "$out" | sed -n 's/^SIGCMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^SIGCMP_FAIL //p')
r=$(printf '%s\n' "$out" | sed -n 's/^SIGCMP_REFUSED //p')
[ -n "$p" ] || { echo "sigcmp.py produced no count"; exit 2; }
echo "ok   signatures: $p facts agree with openssl, $f disagree, $r refused"
pass=$((pass + p))
fail=$((fail + f))

# The coverage categories jarsigner's output has no word for. These are
# asserted against expected numbers rather than against another tool,
# because no other tool reports them; the agreement with jarsigner on
# the verdict and on the per-entry flags is the section below. Each
# number is one the corpus was built to produce.
echo "--- coverage categories, which no other tool names"
for want in \
	"good-rsa unsigned=0 uncovered=0 mismatched=0 partial=0 signed=14" \
	"added unsigned=1 uncovered=0 mismatched=0 partial=0 signed=14" \
	"partial unsigned=0 uncovered=0 mismatched=0 partial=1 signed=14" \
	"tampered unsigned=0 uncovered=0 mismatched=1 partial=0 signed=13" \
	"sigflip unsigned=0 uncovered=14 mismatched=0 partial=0 signed=0" \
	"unsigned unsigned=14 uncovered=0 mismatched=0 partial=0 signed=0" \
	"two-signers unsigned=0 uncovered=0 mismatched=0 partial=0 signed=14"
do
	j=${want%% *}
	line=$("$root/jarv" --verify "$work/$j.jar" | sed -n 's/^summary //p')
	miss=""
	for kv in ${want#* }; do
		case " $line " in
		*" $kv "*) ;;
		*) miss="$miss $kv" ;;
		esac
	done
	if [ -z "$miss" ]; then
		ok "$j.jar: ${want#* }"
	else
		bad "$j.jar: expected$miss, got: $line"
	fi
done

# partial.jar is also the only archive where a signature file is tied to
# the manifest section by section rather than by one digest over the
# whole file, because adding a member staled the first signer's
# whole-manifest digest. Both routes have to be exercised or half of
# Verify.link is dead code that nothing reads.
routes=$("$root/jarv" --verify "$work/partial.jar" | sed -n 's/.* link=\([a-z]*\) .*/\1/p' | sort -u | tr '\n' ',')
if [ "$routes" = "manifest,sections," ]; then
	ok "partial.jar: one signer linked by the whole manifest, one by sections"
else
	bad "partial.jar: link routes are $routes"
fi

# A policy difference, written down rather than smoothed over.
# jarsigner signs sha1.jar and then reports it as UNSIGNED, because
# SHA-1 is in the JDK's disabled list; the signature is real and the
# word is wrong. jarv refuses it and says which algorithm. Both halves
# are asserted so that neither tool quietly changes its mind.
"$root/jarv" --verify "$work/sha1.jar" > "$work/sha1.out" 2>&1
rc=$?
jarsigner -verify "$work/sha1.jar" > "$work/sha1.js" 2>&1
if [ "$rc" = 3 ] && grep -q "^WEAK " "$work/sha1.out" \
		&& grep -q "will be treated as unsigned" "$work/sha1.js"; then
	ok "sha1.jar: jarsigner calls it unsigned, jarv refuses it, exit 3"
else
	bad "sha1.jar: jarv exit $rc, $(head -1 "$work/sha1.out"), jarsigner:" \
		"$(head -1 "$work/sha1.js")"
fi

# A declared non-goal, checked the way a non-goal has to be checked:
# the oracle must ACCEPT the archive and jarv must refuse it cleanly.
# The failure mode of a missing feature is not a missing error message,
# it is quietly accepting something that looked close enough.
"$root/jarv" --verify "$work/dsa.jar" > "$work/dsa.out" 2>&1
rc=$?
jarsigner -verify "$work/dsa.jar" > "$work/dsa.js" 2>&1
if [ "$rc" = 3 ] && grep -q "^jar refused" "$work/dsa.out" \
		&& grep -q "jar verified." "$work/dsa.js"; then
	ok "dsa.jar: jarsigner verifies it and jarv refuses it, exit 3"
else
	bad "dsa.jar: jarv exit $rc, $(head -1 "$work/dsa.out")"
fi
# And the refusal must not be mistaken for a rejection anywhere.
if grep -q "^UNCOVERED" "$work/dsa.out" && ! grep -q "^jar rejected" \
		"$work/dsa.out"; then
	ok "dsa.jar: entries reported as uncovered, archive not rejected"
else
	bad "dsa.jar: refusal reported as something else"
fi

# Certificate validity against a clock the suite sets. Without
# JARV_NOW an expiry test passes today because the certificate has not
# expired, and would pass in ten years because it has: the same green
# line for opposite reasons. The dates themselves are compared against
# openssl in the PKCS7 section; what is checked here is that they are
# used.
echo "--- certificate validity, against JARV_NOW rather than the wall clock"
notafter=$("$root/jarv" --pkcs7 "$work/good-rsa.jar" \
	| sed -n 's/^certnotafter [^ ]* 0 //p')
for probe in "0 notyetvalid=1 the epoch" \
		"4102444800 expired=1 the year 2100"; do
	t=${probe%% *}
	rest=${probe#* }
	kv=${rest%% *}
	when=${rest#* }
	line=$(JARV_NOW=$t "$root/jarv" --verify "$work/good-rsa.jar" \
		| sed -n 's/^signer 0 //p')
	case " $line " in
	*" $kv "*) ok "good-rsa.jar at $when: $kv" ;;
	*) bad "good-rsa.jar at $when: expected $kv in: $line" ;;
	esac
done
line=$("$root/jarv" --verify "$work/good-rsa.jar" | sed -n 's/^signer 0 //p')
for kv in expired=0 notyetvalid=0; do
	case " $line " in
	*" $kv "*) ok "good-rsa.jar now: $kv, and notAfter is $notafter" ;;
	*) bad "good-rsa.jar now: expected $kv in: $line" ;;
	esac
done
line=$("$root/jarv" --verify "$work/expired.jar" | sed -n 's/^signer 0 //p')
case " $line " in
*" expired=1 "*) ok "expired.jar now: expired=1" ;;
*) bad "expired.jar now: expected expired=1 in: $line" ;;
esac

# ------------- oracle: jarsigner -verify -verbose, per entry and per archive
echo "--- oracle: jarsigner -verify -verbose, the headline comparison"
out=$(python3 "$here/jscmp.py" "$root/jarv" $jars)
printf '%s\n' "$out" | grep -E '^(FAIL|refused)' || true
p=$(printf '%s\n' "$out" | sed -n 's/^JSCMP_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^JSCMP_FAIL //p')
r=$(printf '%s\n' "$out" | sed -n 's/^JSCMP_REFUSED //p')
[ -n "$p" ] || { echo "jscmp.py produced no count"; exit 2; }
echo "ok   jarsigner: $p facts agree, $f disagree, $r refused"
pass=$((pass + p))
fail=$((fail + f))

# ---- crafted encoded messages, signed with the corpus private key, with
# ---- jarsigner as the oracle in both directions
echo "--- crafted PKCS#1 encoded messages, against jarsigner"
mkdir -p "$work/em"
out=$(python3 "$here/emcases.py" "$root/jarv" "$work/em" "$work")
printf '%s\n' "$out" | grep '^FAIL' || true
p=$(printf '%s\n' "$out" | sed -n 's/^EMCASE_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^EMCASE_FAIL //p')
[ -n "$p" ] || { echo "emcases.py produced no count"; exit 2; }
echo "ok   encoded messages: $p agree with jarsigner, $f disagree"
pass=$((pass + p))
fail=$((fail + f))

# ---------------- truncation and corruption, against jarsigner
echo "--- truncation and corruption sweep, against jarsigner"
mkdir -p "$work/fuzz"
out=$(python3 "$here/fuzz.py" "$root/jarv" "$work/fuzz" \
	"$work/good-rsa.jar" "$work/good-ec.jar" "$work/zip64.jar" \
	"$work/stored.jar" "$work/added.jar")
printf '%s\n' "$out" | grep '^FAIL' || true
p=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_PASS //p')
f=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_FAIL //p')
r=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_REFUSED //p')
rj=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_REFUSED_JARV //p')
ro=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_REFUSED_ORACLE //p')
m=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_MATCHED //p')
cr=$(printf '%s\n' "$out" | sed -n 's/^FUZZ_CRASH //p')
[ -n "$p" ] || { echo "fuzz.py produced no count"; exit 2; }
echo "ok   corruption: $p agree, $f disagree, $m both declined," \
	"$r one declined ($rj jarv, $ro jarsigner), $cr crashes"
# Every case is one check, whichever column it lands in: jarv ended in
# one of its own exit codes and did not contradict jarsigner. Counting
# only the agreements would make the suite total depend on which bytes
# this run's keys happened to have, since a one-sided refusal and an
# agreement are the same assertion passing.
pass=$((pass + p + m + r))
fail=$((fail + f))

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
