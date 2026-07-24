#!/bin/sh
# Build the jar corpus into $1.
#
# Everything here is made by keytool, jar and jarsigner. The keystore and the
# private keys in it are generated fresh on every run and live only inside the
# caller's mktemp directory: a test key committed to a repository is still a
# key, and the collection's audit scans every object of every repository for
# exactly that.
#
# The password is read from /dev/urandom for the same reason. It is passed on
# the command line, which is visible in ps(1) for the lifetime of each call.
# That is acceptable for a key that exists for the duration of one test run
# and is deleted with the directory.
set -eu

w=$1
mkdir -p "$w"
KS=$w/ks.p12
PW=$(head -c 18 /dev/urandom | base64 | tr -d '\n')
echo "$PW" > "$w/.pw"
chmod 600 "$w/.pw"

kt() { keytool -keystore "$KS" -storepass "$PW" -storetype PKCS12 "$@"; }
js() { jarsigner -keystore "$KS" -storepass "$PW" "$@"; }

# ---------------------------------------------------------------- key material
kt -genkeypair -alias rsa1 -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
	-dname "CN=jarv rsa one, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
kt -genkeypair -alias rsa2 -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
	-dname "CN=jarv rsa two, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
kt -genkeypair -alias ec1 -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
	-dname "CN=jarv ec one, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
# P-384 and P-521 as well, because the three curves are different code
# paths and P-521 is the one where the group order is not a whole number
# of bytes. A digest truncated to 66 bytes instead of to 521 bits keeps
# seven bits too many and rejects every valid signature.
kt -genkeypair -alias ec384 -keyalg EC -groupname secp384r1 \
	-sigalg SHA384withECDSA \
	-dname "CN=jarv ec p384, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
kt -genkeypair -alias ec521 -keyalg EC -groupname secp521r1 \
	-sigalg SHA512withECDSA \
	-dname "CN=jarv ec p521, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
# A real two-certificate chain. Every other key here is self-signed, so
# issuer and subject are the same string and nothing can tell them
# apart: a mutation that swapped the two survived the whole suite for
# exactly that reason.
kt -genkeypair -alias ca -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
	-dname "CN=jarv root ca, OU=corpus, O=jarv" -validity 3650 -ext bc:c \
	>/dev/null 2>&1
kt -genkeypair -alias leaf -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
	-dname "CN=jarv leaf, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
kt -certreq -alias leaf -file "$w/leaf.csr" >/dev/null 2>&1
kt -gencert -alias ca -infile "$w/leaf.csr" -outfile "$w/leaf.cer" -rfc \
	-validity 3000 >/dev/null 2>&1
kt -exportcert -alias ca -rfc -file "$w/ca.cer" >/dev/null 2>&1
cat "$w/leaf.cer" "$w/ca.cer" > "$w/chain.pem"
kt -importcert -alias leaf -file "$w/chain.pem" -noprompt >/dev/null 2>&1
# DSA is a declared non-goal. The corpus carries one anyway, because
# the failure mode of a missing feature is not a missing error message,
# it is quietly accepting something that looked close enough. jarsigner
# verifies this archive and jarv has to refuse it cleanly and be
# counted as having refused, not as having agreed.
kt -genkeypair -alias dsa1 -keyalg DSA -keysize 2048 -sigalg SHA256withDSA \
	-dname "CN=jarv dsa, OU=corpus, O=jarv" -validity 3650 >/dev/null 2>&1
# Starts three years ago and lasts a day, so it is expired now. keytool will
# happily make one; jarsigner warns when signing with it and warns again when
# verifying, which is the second verdict the corpus needs.
kt -genkeypair -alias old1 -keyalg RSA -keysize 2048 -sigalg SHA256withRSA \
	-dname "CN=jarv expired, OU=corpus, O=jarv" -startdate -1095d -validity 1 \
	>/dev/null 2>&1

# ------------------------------------------------------------------- contents
c=$w/c
mkdir -p "$c/a/b"
printf 'alpha\n' > "$c/alpha.txt"
printf 'beta beta beta beta beta beta beta beta beta beta\n' > "$c/beta.txt"
printf 'nested\n' > "$c/a/b/nested.txt"
head -c 4096 /dev/urandom > "$c/a/blob.bin"
: > "$c/empty.txt"

# Names chosen to put a manifest "Name: " line on each side of the 72-byte
# fold and exactly on it. "Name: " is six bytes, so a 66-byte name gives a
# 72-byte line with no fold and a 67-byte name gives the first fold.
for n in 62 65 66 67 68 72; do
	nm=$(python3 -c "import sys; print('f' * (int(sys.argv[1]) - 4) + '.txt')" "$n")
	printf 'len %s\n' "$n" > "$c/$nm"
done

# A name with a space exactly at the fold, so the continuation line begins
# with two spaces: the marker, and one that belongs to the value. A reader
# that strips leading whitespace instead of exactly one character loses it
# and then matches no archive member. 66 bytes before the space puts it on
# the boundary, because "Name: " is six and the first line holds 72.
python3 -c "
import sys, os
open(os.path.join(sys.argv[1], 'x' * 66 + ' y.txt'), 'w').write('spaced\n')
" "$c"

# A name whose UTF-8 encoding is split by the fold in the middle of a
# character. One ASCII byte then 22 three-byte characters is 67 bytes, so
# the first line carries "Name: " plus 66 bytes of it and the break lands
# after the second byte of the 22nd character. A reader that decodes each
# physical line before joining them cannot put that name back together.
python3 - "$c" <<'PYEOF'
import sys, os
d = sys.argv[1]
name = "u" + "\u4e2d" * 22
assert len(name.encode()) == 67, len(name.encode())
open(os.path.join(d, name), "w").write("split\n")
open(os.path.join(d, "\u00e9\u00e8.txt"), "w").write("accents\n")
PYEOF

mk() { (cd "$c" && jar cf "$w/$1.jar" .) ; }

mk base
cp "$w/base.jar" "$w/unsigned.jar"

cp "$w/base.jar" "$w/good-rsa.jar"
js "$w/good-rsa.jar" rsa1 >/dev/null

cp "$w/base.jar" "$w/good-ec.jar"
js "$w/good-ec.jar" ec1 >/dev/null

cp "$w/base.jar" "$w/ec384.jar"
js -digestalg SHA-384 -sigalg SHA384withECDSA "$w/ec384.jar" ec384 >/dev/null

cp "$w/base.jar" "$w/ec521.jar"
js -digestalg SHA-512 -sigalg SHA512withECDSA "$w/ec521.jar" ec521 >/dev/null

cp "$w/base.jar" "$w/chain.jar"
js "$w/chain.jar" leaf >/dev/null

# Entry digests in SHA-1. jarsigner still writes one and then refuses
# to treat the result as signed, because SHA-1 is in its disabled list.
# jarv refuses it too, for a different reason and with a different
# word, and the two answers are recorded as a policy difference rather
# than as an agreement.
cp "$w/base.jar" "$w/sha1.jar"
js -digestalg SHA-1 -sigfile SHAONE "$w/sha1.jar" rsa1 >/dev/null 2>&1

cp "$w/base.jar" "$w/dsa.jar"
js -sigalg SHA256withDSA "$w/dsa.jar" dsa1 >/dev/null

cp "$w/base.jar" "$w/good-sha512.jar"
js -digestalg SHA-512 -sigalg SHA512withRSA "$w/good-sha512.jar" rsa1 >/dev/null

cp "$w/base.jar" "$w/expired.jar"
js "$w/expired.jar" old1 >/dev/null 2>&1

cp "$w/base.jar" "$w/two-signers.jar"
js -sigfile FIRST "$w/two-signers.jar" rsa1 >/dev/null
js -sigfile SECOND "$w/two-signers.jar" rsa2 >/dev/null

# An entry one signer covers and the other does not. Sign with rsa1,
# add a member with jar uf, then sign with rsa2: the second jarsigner
# run writes a manifest section for the new member and digests it in
# its own .SF, while the first signer's .SF never mentioned it and its
# whole-manifest digest is now stale. So the archive is signed twice
# and one member is covered once.
cp "$w/base.jar" "$w/partial.jar"
js -sigfile FIRST "$w/partial.jar" rsa1 >/dev/null
printf 'arrived between the two signatures\n' > "$w/late.txt"
(cd "$w" && jar uf partial.jar late.txt)
rm -f "$w/late.txt"
js -sigfile SECOND "$w/partial.jar" rsa2 >/dev/null

# ------------------------------------------- containers jarsigner cannot make
# jarsigner rewrites the archive it signs with ZipOutputStream, so a signed
# zip64 or stored-entry archive has to be built by rebuilding the container
# afterwards. The signature covers entry contents and manifest bytes and
# says nothing about the container, so a rebuild must leave it valid.
M="python3 $(dirname "$0")/mkzip.py"
$M rebuild "$w/good-rsa.jar" "$w/zip64.jar" --zip64 --no-dd
$M rebuild "$w/good-rsa.jar" "$w/zip64-store.jar" --zip64 --store
$M rebuild "$w/good-rsa.jar" "$w/stored.jar" --store
$M rebuild "$w/good-rsa.jar" "$w/nodd.jar" --no-dd
$M rebuild "$w/good-rsa.jar" "$w/comment.jar" --comment "a trailing comment, which the end record scan has to step over"
# The JDK refuses this one outright: zip64 plus a data descriptor gives
# "invalid entry size (expected 0 but got 582 bytes)" from java.util.zip
# before jarsigner sees a signature at all. Kept in the corpus as a case
# where the oracle refuses and jarv must be counted as unmatched rather
# than as agreeing.
$M rebuild "$w/good-rsa.jar" "$w/zip64-dd.jar" --zip64
# Only the local header offset moved into the zip64 extra field, which is
# the sparse central-directory case: a reader taking all four values in
# order reads the offset as the uncompressed size.
$M rebuild "$w/good-rsa.jar" "$w/zip64-partial.jar" --zip64-partial --no-dd
# Two more things that look like an end of central directory record, one
# before the real one inside a stored entry and one after it in the
# archive comment. See mkzip.py's decoy().
$M decoy "$w/good-rsa.jar" "$w/decoy.jar"

# ------------------------------------------------------- after-the-fact edits
printf 'this entry was never in the manifest\n' \
	| $M add "$w/good-rsa.jar" "$w/added.jar" smuggled.txt
printf 'ALPHA\n' | $M replace "$w/good-rsa.jar" "$w/tampered.jar" alpha.txt
$M bitflip "$w/good-rsa.jar" "$w/bitflip.jar" a/blob.bin 100
$M drop "$w/good-rsa.jar" "$w/dropped.jar" beta.txt
# One bit of the signature block, which is the last byte of the
# encryptedDigest because nothing follows it in the SignerInfo. Nothing
# in the manifest covers a signature block, so this breaks the signature
# and nothing else.
$M bitflip "$w/good-rsa.jar" "$w/sigflip.jar" META-INF/RSA1.RSA -1

rm -f "$w/base.jar"
echo "corpus in $w"
