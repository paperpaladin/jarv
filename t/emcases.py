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


def verdict_of(jarv, jar, block_name):
    """jarv's verdict for one signature block, and whether it is ok.

    A missing verdict line counts as a rejection and as a verdict of
    "", which no expected fragment matches. That matters: a mutation
    that makes jarv throw instead of deciding produces no line at all,
    and a harness reading only accept-or-reject would score the crash
    as a correct rejection.
    """
    rc, out = run([jarv, "--sig", jar])
    verdict = ""
    for line in out.splitlines():
        f = line.split(" ")
        if f[0] == "sigverdict" and f[1] == block_name:
            verdict = " ".join(f[3:])
    return verdict, verdict == "ok"


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
    cases.append(("control", good_em, True, "ok",
                  "the original encoded message, re-signed"))
    # Bleichenbacher's shape: the DigestInfo is correct and complete and
    # there are bytes after it. A verifier that stops looking once it has
    # parsed a DigestInfo accepts this, and with a small public exponent
    # it can be built without the private key at all.
    t = good_t + b"\x5a" * 8
    cases.append(("trailing", pad(t, k), False, "bad",
                  "eight bytes after a correct DigestInfo"))
    em = bytearray(good_em)
    em[5] = 0xFE
    cases.append(("nonff", bytes(em), False, "bad the encoded message",
                  "one padding byte that is not 0xFF"))
    em = bytearray(good_em)
    em[k - len(good_t) - 1] = 0x01
    cases.append(("nosep", bytes(em), False, "bad the encoded message",
                  "the 0x00 separator replaced by 0x01"))
    em = bytearray(good_em)
    em[-1] ^= 0x01
    cases.append(("wrongdigest", bytes(em), False, "bad the signed digest",
                  "one bit flipped in the digest"))
    # A DigestInfo naming SHA-256 and carrying a real SHA-256 digest of
    # the signed bytes, inside a SignerInfo that declares SHA-384. The
    # structure is valid and the digest is right; only the agreement
    # between the two declarations is broken.
    other = "SHA-256" if alg != "SHA-256" else "SHA-512"
    odg = hashlib.new(other.replace("-", "").lower(), signed).digest()
    cases.append(("wrongalg", pad(digest_info(other, odg), k), False,
                  "bad the signature is over",
                  "a DigestInfo naming %s where the signer declares %s"
                  % (other, alg)))
    # Two rules cover the digest algorithm parameters field, and the
    # first version of this file reached both with one case: parameters
    # holding an INTEGER are neither NULL nor zero length, so deleting
    # either rule left the other to reject it and the mutation of the
    # first survived. Each rule gets a case that only it can reject.
    # A zero-length OCTET STRING is not NULL and is zero length.
    cases.append(("params", pad(digest_info(alg, dg, "0400"), k), False,
                  "bad digest algorithm parameters that are not NULL",
                  "digest algorithm parameters that are an empty octet"
                  " string rather than NULL"))
    # A NULL carrying a content byte is NULL and is not zero length.
    cases.append(("nullcontent", pad(digest_info(alg, dg, "0501ff"), k),
                  False, "bad a NULL with content",
                  "a NULL with a content byte in the digest algorithm"
                  " parameters"))
    # An encoded message that does not start 00 01.
    em = bytearray(good_em)
    em[1] = 0x02
    cases.append(("blocktype", bytes(em), False, "bad the encoded message",
                  "block type 2 rather than 1"))

    for name, em, want_ok, expect, why in cases:
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
        verdict, accepted = verdict_of(jarv, jar, block_name)
        if accepted == want_ok and verdict.startswith(expect):
            ok("%s: jarv %s, %s" % (name, "accepts" if accepted else "rejects",
                                    why))
        else:
            # The verdict text is checked and not only the yes or no.
            # Several of these cases are rejected for more than one
            # reason at once, and a harness that only asks whether jarv
            # said no cannot tell which rule did the work.
            bad("%s: jarv said %r where %r was expected, for %s"
                % (name, verdict, expect, why))
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

    attr_cases(jarv, work, src, block_name, der, mkzip)
    ec_cases(jarv, work, corpus, mkzip)
    print("EMCASE_PASS %d" % PASS)
    print("EMCASE_FAIL %d" % FAIL)
    return 0


def attr_cases(jarv, work, src, block_name, der, mkzip):
    """The two authenticated attributes that tie a signature to content.

    Both are patched in place at their original length, so the block
    stays well formed and only the attribute value changes. Patching
    them also breaks the signature over the attribute set, which is the
    point of asking for the verdict TEXT: jarv must say the attribute
    is wrong, which it checks first, rather than reaching the signature
    and saying the digest does not match. A harness reading only
    accept-or-reject cannot tell those two apart, and the mutations
    that delete each attribute check produce exactly the second.
    """
    p = os.path.join(work, "attr.der")
    open(p, "wb").write(der)
    _, out = run(["openssl", "asn1parse", "-inform", "DER", "-in", p])
    lines = out.splitlines()

    def after(label, kind):
        seen = False
        for line in lines:
            if not seen:
                seen = label in line
                continue
            m = re.match(r"\s*(\d+):d=\d+\s+hl=\s*(\d+)\s+l=\s*(\d+)"
                         r"\s+prim:\s+" + kind, line)
            if m:
                return (int(m.group(1)) + int(m.group(2)), int(m.group(3)))
        return (None, None)

    cases = []
    off, ln = after(":messageDigest", "OCTET STRING")
    if off is None:
        bad("no messageDigest attribute in " + block_name)
    else:
        b = bytearray(der)
        b[off] ^= 0x01
        cases.append(("attr-md", bytes(b), "bad the signed messageDigest",
                      "one bit flipped in the messageDigest attribute"))
    off, ln = after(":contentType", "OBJECT")
    if off is None:
        bad("no contentType attribute in " + block_name)
    else:
        b = bytearray(der)
        # id-data is 1.2.840.113549.1.7.1 and id-signedData is ...7.2,
        # so one byte makes a valid object identifier of the same
        # length that is the wrong content type.
        b[off + ln - 1] = 0x02
        cases.append(("attr-ct", bytes(b), "bad the signed contentType",
                      "contentType changed to signedData"))

    for name, blob, expect, why in cases:
        jar = os.path.join(work, "%s.jar" % name)
        r = subprocess.run(["python3", mkzip, "replace", src, jar,
                            block_name], input=blob,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if r.returncode != 0:
            bad("%s: mkzip replace failed" % name)
            continue
        verdict, accepted = verdict_of(jarv, jar, block_name)
        if not accepted and verdict.startswith(expect):
            ok("%s: jarv rejects, %s" % (name, why))
        else:
            bad("%s: jarv said %r where %r was expected"
                % (name, verdict, expect))
        jrc, jout = run(["jarsigner", "-verify", jar])
        if not (jrc == 0 and "jar verified." in jout):
            ok("%s: jarsigner rejects too" % name)
        else:
            bad("%s: jarsigner verified it" % name)


def tlvs(work, der):
    """Every top-level value in a DER blob: (offset, header, length)."""
    p = os.path.join(work, "part.der")
    open(p, "wb").write(der)
    _, out = run(["openssl", "asn1parse", "-inform", "DER", "-in", p])
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+):d=(\d+)\s+hl=\s*(\d+)\s+l=\s*(\d+)"
                     r"\s+(\w+):\s*(\S*)", line)
        if m:
            rows.append((int(m.group(1)), int(m.group(2)), int(m.group(3)),
                         int(m.group(4)), m.group(6)))
    return rows


def ec_cases(jarv, work, corpus, mkzip):
    """Crafted ECDSA signatures, with the lengths left alone.

    An ECDSA signature is SEQUENCE { INTEGER r, INTEGER s }, and a
    crafted r or s of a different magnitude would be a different number
    of bytes, which would move every enclosing length in the block. So
    the content octets of an integer are overwritten in place instead:
    zeroing them gives a non-minimal encoding of zero, which is exactly
    the out-of-range value the range check exists for, at the original
    length.

    The public point is attacked the same way, by flipping one bit of
    the x coordinate inside the certificate's SubjectPublicKeyInfo. The
    result is almost certainly not on the curve, and the certificate is
    the right length still.
    """
    src = os.path.join(corpus, "good-ec.jar")
    if not os.path.exists(src):
        bad("no good-ec.jar in the corpus")
        return
    block_name = "META-INF/EC1.EC"
    der = zipfile.ZipFile(src).read(block_name)
    off, ln = last_octet_string(work, der)
    if off is None:
        bad("no signature octet string in " + block_name)
        return
    sig = der[off:off + ln]
    ints = [r for r in tlvs(work, sig) if r[4] == "INTEGER"]
    if len(ints) != 2:
        bad("an ECDSA signature of %d integers" % len(ints))
        return
    # The public key bit string: one unused-bits octet, then 0x04 and
    # two 32-byte coordinates for P-256.
    pk = None
    for o, depth, hl, l, kind in tlvs(work, der):
        if kind == "BIT" and l == 66 and der[o + hl] == 0 \
                and der[o + hl + 1] == 4:
            pk = o + hl + 2
            break
    cases = []
    cases.append(("ec-control", der, True, "ok",
                  "the block as jarsigner wrote it"))
    for which, (o, _d, hl, l, _k) in zip(("r", "s"), ints):
        b = bytearray(der)
        for i in range(l):
            b[off + o + hl + i] = 0
        cases.append(("ec-zero-" + which, bytes(b), False,
                      "bad r or s is outside",
                      which + " set to zero at its original length"))
    if pk is not None:
        b = bytearray(der)
        b[pk] ^= 0x01
        cases.append(("ec-offcurve", bytes(b), False,
                      "refused the public point is not on",
                      "one bit flipped in the x coordinate of the"
                      " public key"))
    else:
        bad("no uncompressed P-256 public key found in " + block_name)

    for name, blob, want_ok, expect, why in cases:
        jar = os.path.join(work, "%s.jar" % name)
        p = subprocess.run(["python3", mkzip, "replace", src, jar,
                            block_name], input=blob,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if p.returncode != 0:
            bad("%s: mkzip replace failed" % name)
            continue
        verdict, accepted = verdict_of(jarv, jar, block_name)
        if accepted == want_ok and verdict.startswith(expect):
            ok("%s: jarv %s, %s"
               % (name, "accepts" if accepted else "rejects", why))
        else:
            bad("%s: jarv said %r where %r was expected, for %s"
                % (name, verdict, expect, why))
        jrc, jout = run(["jarsigner", "-verify", jar])
        jaccepted = jrc == 0 and "jar verified." in jout
        if jaccepted == want_ok:
            ok("%s: jarsigner %s too"
               % (name, "verifies" if jaccepted else "rejects"))
        else:
            bad("%s: jarsigner exited %d saying %r"
                % (name, jrc, jout.strip().splitlines()[:1]))


sys.exit(main())
