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

mk() { (cd "$c" && jar cf "$w/$1.jar" .) ; }

mk base
cp "$w/base.jar" "$w/unsigned.jar"

cp "$w/base.jar" "$w/good-rsa.jar"
js "$w/good-rsa.jar" rsa1 >/dev/null

cp "$w/base.jar" "$w/good-ec.jar"
js "$w/good-ec.jar" ec1 >/dev/null

cp "$w/base.jar" "$w/good-sha512.jar"
js -digestalg SHA-512 -sigalg SHA512withRSA "$w/good-sha512.jar" rsa1 >/dev/null

cp "$w/base.jar" "$w/expired.jar"
js "$w/expired.jar" old1 >/dev/null 2>&1

cp "$w/base.jar" "$w/two-signers.jar"
js -sigfile FIRST "$w/two-signers.jar" rsa1 >/dev/null
js -sigfile SECOND "$w/two-signers.jar" rsa2 >/dev/null

rm -f "$w/base.jar"
echo "corpus in $w"
