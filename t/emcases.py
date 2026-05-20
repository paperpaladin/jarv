#!/usr/bin/env python3
"""Crafted PKCS#1 v1.5 encoded messages, signed with the corpus key.

Every signature in the corpus is well formed, so none of the rules in
Rsa.unpad and Rsa.digestInfo is reachable from it. Five mutations of
those rules were run and all five survived. This file reaches them.

The corpus keystore holds the private key, so a signature over any
chosen encoded message can be produced: the raw RSA operation is
s = m^d mod n, done here with Python's pow over the modulus and private
exponent that openssl rsa -text prints. openssl's own pkeyutl refuses a
256-byte input to -sign with rsa_padding_mode:none, and rsautl -raw is
deprecated, so the arithmetic is done directly rather than fought with.
Doing it in Python also keeps the crafting independent of the openssl
code path that later judges the result.

Each case replaces the signature octets inside META-INF/RSA1.RSA of
good-rsa.jar, leaving the length unchanged, and rebuilds the archive.
The signature block is not covered by any digest in the manifest, so
nothing else in the jar has to change.

The first case re-signs the ORIGINAL encoded message. It must be
ACCEPTED, by jarv and by jarsigner. Without it every later rejection
could come from the splicing rather than from the crafted bytes, and a
harness that only ever asserts rejection cannot tell the difference.

Two oracles per case: jarsigner -verify, and openssl dgst -verify over
the bytes jarv nominates as signed.

Prints EMCASE_PASS n, EMCASE_FAIL n.
"""
import binascii
import os
import re
import subprocess
import sys
import zipfile

PASS = 0
FAIL = 0


def ok(m):
    global PASS
    PASS += 1
    print("ok   " + m)


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def run(cmd, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       **kw)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def rsa_key(pem):
    """Modulus and private exponent, from openssl rsa -text."""
    _, t = run(["openssl", "rsa", "-in", pem, "-text", "-noout"])

    def field(name):
        m = re.search(name + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", t)
        if m:
            return int(re.sub(r"[\s:]", "", m.group(1)), 16)
        m = re.search(name + r":\s*(\d+)", t)
        return int(m.group(1))

    return field("modulus"), field("privateExponent")


def private_keys(work, keystore, password):
    """Every private key in the keystore, by its keytool alias."""
    out = os.path.join(work, "keys.pem")
    rc, msg = run(["openssl", "pkcs12", "-in", keystore, "-passin",
                   "pass:" + password, "-nodes", "-nocerts", "-out", out])
    if rc != 0:
        return {}
    text = open(out).read()
    keys = {}
    for part in re.split(r"(?=Bag Attributes)", text):
        name = re.search(r"friendlyName: (\S+)", part)
        body = re.search(
            r"-----" + "BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
            part, re.S)
        if name and body:
            keys[name.group(1)] = body.group(0) + "\n"
    return keys


def last_octet_string(work, der):
    """Offset and length of the final OCTET STRING, per openssl asn1parse.

    That is the encryptedDigest of the last SignerInfo. Located with
    openssl rather than with jarv, so the splice does not depend on the
    decoder under test agreeing about where the signature is.
    """
    p = os.path.join(work, "blk.der")
    open(p, "wb").write(der)
    _, out = run(["openssl", "asn1parse", "-inform", "DER", "-in", p])
    lines = [l for l in out.splitlines() if "OCTET STRING" in l]
    if not lines:
        return None, None
    line = lines[-1]
    off = int(line.split(":")[0])
    hl = int(re.search(r"hl=\s*(\d+)", line).group(1))
    # "l=" also matches inside "hl=", so the h must be excluded.
    ln = int(re.search(r"(?<!h)l=\s*(\d+)", line).group(1))
    return off + hl, ln


DIGEST_OID = {
    "SHA-1": "06052b0e03021a",
    "SHA-256": "0609608648016503040201",
    "SHA-384": "0609608648016503040202",
    "SHA-512": "0609608648016503040203",
}


def digest_info(alg, digest, params="0500"):
    """DER DigestInfo, built by hand so the parameters can be anything."""
    algid = binascii.unhexlify(DIGEST_OID[alg] + params)
    algid = b"\x30" + bytes([len(algid)]) + algid
    octets = b"\x04" + bytes([len(digest)]) + digest
    body = algid + octets
    return b"\x30" + bytes([len(body)]) + body


def pad(t, k):
    """EM = 00 01 FF... 00 T, filling k bytes."""
    return b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t


def main():
    jarv = sys.argv[1]
    work = sys.argv[2]
    corpus = sys.argv[3]
    os.makedirs(work, exist_ok=True)
    here = os.path.dirname(os.path.abspath(__file__))
    mkzip = os.path.join(here, "mkzip.py")
    src = os.path.join(corpus, "good-rsa.jar")
    pwfile = os.path.join(corpus, ".pw")
    if not os.path.exists(pwfile):
        print("FAIL no keystore password in the corpus directory")
        print("EMCASE_PASS 0")
        print("EMCASE_FAIL 1")
        return 1
    password = open(pwfile).read().strip()
    keys = private_keys(work, os.path.join(corpus, "ks.p12"), password)
    if "rsa1" not in keys:
        print("FAIL could not read the rsa1 private key out of the keystore")
        print("EMCASE_PASS 0")
        print("EMCASE_FAIL 1")
        return 1
    pem = os.path.join(work, "rsa1.pem")
    open(pem, "w").write(keys["rsa1"])
    n, d = rsa_key(pem)
    k = (n.bit_length() + 7) // 8

    block_name = "META-INF/RSA1.RSA"
    der = zipfile.ZipFile(src).read(block_name)
    off, ln = last_octet_string(work, der)
    if off is None or ln != k:
        print("FAIL the last octet string in the block is %r bytes, not %d"
              % (ln, k))
        print("EMCASE_PASS 0")
        print("EMCASE_FAIL 1")
        return 1

    # The signed bytes and the digest algorithm come from jarv, and are
    # then checked by openssl dgst on the control case: if jarv were
    # wrong about either, the control case would be rejected and the
    # whole file would report a failure rather than a row of successes.
    rc, out = run([jarv, "--sig", src])
    signed = None
    alg = None
    for line in out.splitlines():
        f = line.split(" ")
        if f[0] == "sigsigned" and f[1] == block_name:
            signed = binascii.unhexlify(f[3])
        if f[0] == "sigalg" and f[1] == block_name:
            for kv in f[3:]:
                a, _, b = kv.partition("=")
                if a == "digest":
                    alg = b
    if signed is None or alg is None:
        print("FAIL jarv printed no signed bytes for " + block_name)
        print("EMCASE_PASS 0")
        print("EMCASE_FAIL 1")
        return 1

    import hashlib
    hname = alg.replace("-", "").lower()
    dg = hashlib.new(hname, signed).digest()
    good_t = digest_info(alg, dg)
    good_em = pad(good_t, k)

    cases = []
    cases.append(("control", good_em, True,
                  "the original encoded message, re-signed"))
    # Bleichenbacher's shape: the DigestInfo is correct and complete and
    # there are bytes after it. A verifier that stops looking once it has
    # parsed a DigestInfo accepts this, and with a small public exponent
    # it can be built without the private key at all.
    t = good_t + b"\x5a" * 8
    cases.append(("trailing", pad(t, k), False,
                  "eight bytes after a correct DigestInfo"))
    em = bytearray(good_em)
    em[5] = 0xFE
    cases.append(("nonff", bytes(em), False,
                  "one padding byte that is not 0xFF"))
    em = bytearray(good_em)
    em[k - len(good_t) - 1] = 0x01
    cases.append(("nosep", bytes(em), False,
                  "the 0x00 separator replaced by 0x01"))
    em = bytearray(good_em)
    em[-1] ^= 0x01
    cases.append(("wrongdigest", bytes(em), False,
                  "one bit flipped in the digest"))
    # A DigestInfo naming SHA-256 and carrying a real SHA-256 digest of
    # the signed bytes, inside a SignerInfo that declares SHA-384. The
    # structure is valid and the digest is right; only the agreement
    # between the two declarations is broken.
    other = "SHA-256" if alg != "SHA-256" else "SHA-512"
    odg = hashlib.new(other.replace("-", "").lower(), signed).digest()
    cases.append(("wrongalg", pad(digest_info(other, odg), k), False,
                  "a DigestInfo naming %s where the signer declares %s"
                  % (other, alg)))
    # Parameters that are an INTEGER rather than NULL. Everything else
    # is correct, so only the parameters rule can reject it.
    cases.append(("params", pad(digest_info(alg, dg, "0201ff"), k), False,
                  "digest algorithm parameters that are an integer"))
    # An encoded message that does not start 00 01.
    em = bytearray(good_em)
    em[1] = 0x02
    cases.append(("blocktype", bytes(em), False,
                  "block type 2 rather than 1"))

    for name, em, want_ok, why in cases:
        if len(em) != k:
            bad("%s: built a %d-byte encoded message for a %d-byte modulus"
                % (name, len(em), k))
            continue
        sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
        patched = der[:off] + sig + der[off + ln:]
        jar = os.path.join(work, "em-%s.jar" % name)
        p = subprocess.run(["python3", mkzip, "replace", src, jar,
                            block_name], input=patched,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if p.returncode != 0:
            bad("%s: mkzip replace failed: %s"
                % (name, p.stdout.decode()[:120]))
            continue
        rc, out = run([jarv, "--sig", jar])
        verdict = ""
        for line in out.splitlines():
            f = line.split(" ")
            if f[0] == "sigverdict" and f[1] == block_name:
                verdict = " ".join(f[3:])
        accepted = verdict == "ok"
        if accepted == want_ok:
            ok("%s: jarv %s, %s" % (name, "accepts" if accepted else "rejects",
                                    why))
        else:
            bad("%s: jarv said %r for %s" % (name, verdict, why))
        jrc, jout = run(["jarsigner", "-verify", jar])
        jaccepted = jrc == 0 and "jar verified." in jout
        if jaccepted == want_ok:
            ok("%s: jarsigner %s too"
               % (name, "verifies" if jaccepted else "rejects"))
        else:
            bad("%s: jarsigner exited %d saying %r"
                % (name, jrc, jout.strip().splitlines()[:1]))
        if accepted != jaccepted:
            bad("%s: jarv and jarsigner disagree, jarv %s and jarsigner %s"
                % (name, verdict, "verified" if jaccepted else "rejected"))

    print("EMCASE_PASS %d" % PASS)
    print("EMCASE_FAIL %d" % FAIL)
    return 0


sys.exit(main())
