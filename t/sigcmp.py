#!/usr/bin/env python3
"""jarv --sig against openssl, for the signature itself.

Three questions per signer, each asked of openssl rather than of jarv:

  1. Does openssl pkeyutl -verifyrecover, given the signature and the
     public key alone, produce the same DigestInfo bytes that jarv's own
     modular exponentiation and PKCS#1 v1.5 unpad produce? This is the
     check on the arithmetic and on the padding together, and it needs
     no digest and no signed content, so it cannot agree by accident
     with the next one.

  2. Does openssl dgst -verify accept jarv's idea of the signed bytes?
     jarv prints the bytes it believes the signature covers. For a
     SignerInfo with authenticated attributes those are the attribute
     set re-tagged from the implicit [0] to a universal SET, and getting
     that wrong is the single easiest way to build a verifier that
     accepts signatures nobody else does. openssl is given the bytes and
     the public key and asked the question directly.

  3. Do the two tools reach the same verdict? openssl's "Verified OK"
     against jarv's ok or bad.

Question 2 is asked for ECDSA blocks as well, even though jarv refuses
to verify them: openssl can verify the bytes jarv nominates, so the
re-tagging is checked for EC signatures too and the verdict is counted
as a refusal rather than as an agreement.

Prints SIGCMP_PASS n, SIGCMP_FAIL n and SIGCMP_REFUSED n.
"""
import binascii
import os
import re
import subprocess
import sys

PASS = 0
FAIL = 0
REFUSED = 0


def ok(m):
    global PASS
    PASS += 1
    print("ok   " + m)


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def refuse(m):
    global REFUSED
    REFUSED += 1
    print("refused " + m)


def run(cmd, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       **kw)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def parse_jarv(text):
    """Keyed by (block, signer index)."""
    sigs = {}
    for line in text.splitlines():
        f = line.split(" ")
        if len(f) < 3 or not f[0].startswith("sig"):
            continue
        if f[0] == "sigbad":
            continue
        key = (f[1], f[2])
        d = sigs.setdefault(key, {})
        if f[0] == "sigalg":
            for kv in f[3:]:
                k, _, v = kv.partition("=")
                d[k] = v
        elif f[0] == "sigverdict":
            d["verdict"] = " ".join(f[3:])
        elif f[0] == "sigkey":
            for kv in f[3:]:
                k, _, v = kv.partition("=")
                d[k] = v
        else:
            d[f[0][3:]] = f[3] if len(f) > 3 else ""
    return sigs


# openssl spells the digest for -dgst in lower case with no hyphen.
DGST = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
        "SHA-384": "sha384", "SHA-512": "sha512", "MD5": "md5"}


def split_pem(text):
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        text, re.S)


def main():
    jarv = sys.argv[1]
    work = sys.argv[2]
    jars = sys.argv[3:]
    os.makedirs(work, exist_ok=True)
    for jar in jars:
        base = os.path.basename(jar)
        rc, out = run([jarv, "--sig", jar])
        if rc not in (0, 3):
            bad("%s: jarv --sig exited %d" % (base, rc))
            continue
        sigs = parse_jarv(out)
        if not sigs:
            continue
        # The blocks, extracted once per jar with python's zipfile so the
        # extraction is not jarv's own container parse.
        blocks = {}
        import zipfile
        try:
            with zipfile.ZipFile(jar) as z:
                for name in set(k[0] for k in sigs):
                    blocks[name] = z.read(name)
        except Exception as e:
            refuse("%s python zipfile: %s" % (base, e))
            continue
        for (block, idx), d in sorted(sigs.items()):
            tag = "%s %s #%s" % (base, block, idx)
            bpath = os.path.join(work, "%s.%s.%s" % (base, idx, "blk"))
            open(bpath, "wb").write(blocks[block])
            rc, pem = run(["openssl", "pkcs7", "-inform", "DER", "-in", bpath,
                           "-print_certs"])
            if rc != 0:
                refuse("%s openssl pkcs7 -print_certs: %s" % (tag, pem[:120]))
                continue
            # Match jarv's chosen signer certificate by fingerprint, so
            # the identification is checked and not assumed.
            want = d.get("cert")
            chosen = None
            for one in split_pem(pem):
                p = os.path.join(work, "c.pem")
                open(p, "w").write(one + "\n")
                rc, fp = run(["openssl", "x509", "-in", p, "-outform", "DER",
                              "-out", p + ".der"])
                rc, h = run(["sha256sum", p + ".der"])
                if h.split()[0] == want:
                    chosen = one
                    break
            if chosen is None:
                bad("%s: the certificate jarv picked (%s) is not one openssl"
                    " finds in the block" % (tag, want))
                continue
            ok("%s: signer certificate agrees with openssl pkcs7 -print_certs"
               % tag)
            cp = os.path.join(work, "signer.pem")
            open(cp, "w").write(chosen + "\n")
            pub = os.path.join(work, "signer.pub")
            rc, _ = run(["openssl", "x509", "-in", cp, "-pubkey", "-noout",
                         "-out", pub])
            if rc != 0:
                refuse("%s openssl could not extract the public key" % tag)
                continue
            sigf = os.path.join(work, "sig.bin")
            open(sigf, "wb").write(binascii.unhexlify(d["bytes"]))
            signedf = os.path.join(work, "signed.bin")
            open(signedf, "wb").write(binascii.unhexlify(d["signed"]))

            if "recovered" in d:
                recf = os.path.join(work, "rec.bin")
                rc, msg = run(["openssl", "pkeyutl", "-verifyrecover",
                               "-pubin", "-inkey", pub, "-in", sigf,
                               "-out", recf])
                if rc != 0:
                    bad("%s: jarv recovered a DigestInfo and openssl"
                        " pkeyutl -verifyrecover would not: %s"
                        % (tag, msg.strip()[:120]))
                else:
                    got = binascii.hexlify(open(recf, "rb").read()).decode()
                    if got == d["recovered"]:
                        ok("%s: DigestInfo matches openssl pkeyutl"
                           " -verifyrecover, %d bytes" % (tag, len(got) // 2))
                    else:
                        bad("%s: jarv recovered %s, openssl recovered %s"
                            % (tag, d["recovered"], got))

            alg = DGST.get(d.get("digest", ""))
            if alg is None:
                refuse("%s: no openssl -dgst name for %s"
                       % (tag, d.get("digest")))
                continue
            rc, msg = run(["openssl", "dgst", "-" + alg, "-verify", pub,
                           "-signature", sigf, signedf])
            accepted = rc == 0 and "Verified OK" in msg
            if accepted:
                ok("%s: openssl dgst -%s -verify accepts the %d bytes jarv"
                   " says are signed" % (tag, alg, len(d["signed"]) // 2))
            else:
                bad("%s: openssl dgst -%s -verify rejects the bytes jarv says"
                    " are signed: %s" % (tag, alg, msg.strip()[:120]))

            v = d.get("verdict", "")
            if v.startswith("refused") and d.get("keytype") == "RSA":
                # A refusal is only honest for something jarv says it does
                # not do, and RSA is not on that list. Counting this one as
                # a refusal would let any mutation that turns verification
                # into a shrug pass the suite, which is exactly what the
                # unused-bits mutant did before this branch existed: it
                # moved 16 agreements into the refused column and the run
                # still printed 0 failed.
                bad("%s: jarv %s for an RSA signature openssl %s"
                    % (tag, v, "accepts" if accepted else "rejects"))
            elif v.startswith("refused"):
                refuse("%s: jarv %s (openssl says %s)"
                       % (tag, v, "verified" if accepted else "rejected"))
            elif (v == "ok") == accepted:
                ok("%s: verdict agrees with openssl, both %s"
                   % (tag, "accept" if accepted else "reject"))
            else:
                bad("%s: jarv says %s and openssl says %s"
                    % (tag, v, "verified" if accepted else "rejected"))

    print("SIGCMP_PASS %d" % PASS)
    print("SIGCMP_FAIL %d" % FAIL)
    print("SIGCMP_REFUSED %d" % REFUSED)
    return 0


sys.exit(main())
