#!/usr/bin/env python3
"""jarv's NIST curve constants against openssl ecparam.

Six constants per curve, typed in by hand from the standard, and the
only thing that catches a typo in one of them is a signature over that
curve failing to verify. P-521's group order had fourteen extra 0xff
bytes in it and nothing noticed until a P-521 jar was added to the
corpus, which is a long way round for a constant openssl will print on
request.

openssl ecparam -param_enc explicit prints the prime, a, b, the
generator and the order for a named curve. Each is compared as an
integer, so leading zeros in either spelling do not matter.

Prints CURVECMP_PASS n and CURVECMP_FAIL n.
"""
import re
import subprocess
import sys

PASS = 0
FAIL = 0

# jarv's name for the curve, openssl's name for the same curve.
NAMES = [("P-256", "prime256v1"), ("P-384", "secp384r1"),
         ("P-521", "secp521r1")]


def ok(m):
    global PASS
    PASS += 1
    print("ok   " + m)


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def openssl_curve(name):
    p = subprocess.run(["openssl", "ecparam", "-name", name, "-param_enc",
                        "explicit", "-text", "-noout"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    t = p.stdout.decode()
    if p.returncode != 0 or "Prime:" not in t:
        return None

    def block(label):
        m = re.search(label + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", t)
        return int(re.sub(r"[\s:]", "", m.group(1)), 16) if m else None

    gen = re.search(r"Generator \(uncompressed\):\s*\n((?:\s+[0-9a-f:]+\n)+)",
                    t)
    g = re.sub(r"[\s:]", "", gen.group(1))
    if not g.startswith("04"):
        return None
    half = (len(g) - 2) // 2
    return {"p": block("Prime"), "a": block("A"), "b": block("B"),
            "n": block("Order"), "gx": int(g[2:2 + half], 16),
            "gy": int(g[2 + half:], 16)}


def main():
    jarv = sys.argv[1]
    p = subprocess.run([jarv, "--curves"], stdout=subprocess.PIPE)
    mine = {}
    for line in p.stdout.decode().splitlines():
        f = line.split(" ")
        if f[0] != "curve":
            continue
        d = {}
        for kv in f[3:]:
            k, _, v = kv.partition("=")
            d[k] = int(v, 16)
        mine[f[2]] = d
    for jname, oname in NAMES:
        want = openssl_curve(oname)
        if want is None:
            bad("openssl ecparam does not know " + oname)
            continue
        got = mine.get(jname)
        if got is None:
            bad("jarv has no curve named " + jname)
            continue
        for field in ("p", "a", "b", "gx", "gy", "n"):
            if got[field] == want[field]:
                ok("%s %s agrees with openssl ecparam" % (jname, field))
            else:
                bad("%s %s: jarv has %x, openssl has %x"
                    % (jname, field, got[field], want[field]))
        # The generator has to be on the curve, which is a check on the
        # five other constants together rather than one at a time.
        lhs = (got["gy"] * got["gy"]) % got["p"]
        rhs = (got["gx"] ** 3 + got["a"] * got["gx"] + got["b"]) % got["p"]
        if lhs == rhs:
            ok("%s: the generator satisfies the curve equation" % jname)
        else:
            bad("%s: the generator is not on the curve jarv describes" % jname)
    print("CURVECMP_PASS %d" % PASS)
    print("CURVECMP_FAIL %d" % FAIL)
    return 0


sys.exit(main())
