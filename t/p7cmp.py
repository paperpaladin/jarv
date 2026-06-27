#!/usr/bin/env python3
"""jarv's PKCS#7 and X.509 parse against openssl pkcs7 -print.

openssl prints the structure it decoded, with numeric OIDs, so the
comparison is on values rather than on the shape of the tree, which
asn1parse already covers. Distinguished names and validity dates are
compared as whole strings, and jarv prints them in openssl's own format
on purpose: a normalisation applied to both sides is a place for a
disagreement to hide.

Facts per block: content type, version, the digest algorithm set, whether
the content is detached, and then per certificate the version, serial,
signature algorithm, key algorithm, issuer, subject and both validity
dates; per signer the version, issuer, serial, digest algorithm,
encryption algorithm and the list of authenticated attribute OIDs.
"""
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


def run(cmd, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       **kw)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def runb(cmd, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       **kw)
    return p.returncode, p.stdout


OIDPAR = re.compile(r"^(.*?)\s+\(([0-9.]+)\)$")


def oid_of(v):
    m = OIDPAR.match(v.strip())
    return m.group(2) if m else v.strip()


def parse_openssl(text):
    out = {"certs": [], "signers": [], "md_algs": []}
    section = "top"
    cur = None
    algs = []
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        # openssl prints one "cert:" header and then a "cert_info:" block
        # per certificate, so the per-certificate delimiter is the second
        # of those. Splitting on "cert:" counted a two-certificate chain
        # as one, and said so only once the corpus grew a chain.
        if stripped == "cert_info:" and indent <= 8:
            cur = {"algs": []}
            out["certs"].append(cur)
            section = "cert"
            continue
        if stripped == "cert:" and indent <= 8:
            section = "top"
            continue
        if stripped == "signer_info:" and indent <= 8:
            cur = {"algs": [], "auth": []}
            out["signers"].append(cur)
            section = "signer"
            continue
        if stripped == "md_algs:":
            section = "md_algs"
            continue
        if stripped == "contents:":
            section = "contents"
            continue
        if ":" not in stripped:
            continue
        k, _, v = stripped.partition(":")
        k = k.strip()
        v = v.strip()
        if section == "top" and k == "type":
            out["type"] = oid_of(v)
        elif section == "top" and k == "version":
            out["version"] = v
        elif section == "md_algs" and k == "algorithm":
            out["md_algs"].append(oid_of(v))
        elif section == "contents" and k == "type":
            out["content_type"] = oid_of(v)
        elif section == "contents" and k == "d.data":
            out["detached"] = (v == "<ABSENT>")
        elif section == "cert":
            if k == "algorithm":
                cur["algs"].append(oid_of(v))
            elif k in ("version", "serialNumber", "issuer", "subject",
                       "notBefore", "notAfter"):
                cur.setdefault(k, v)
        elif section == "signer":
            if k == "algorithm":
                cur["algs"].append(oid_of(v))
            elif k == "object":
                cur["auth"].append(oid_of(v))
            elif k in ("version", "issuer", "serial"):
                cur.setdefault(k, v)
    return out


def parse_jarv(text):
    blocks = {}
    for line in text.splitlines():
        f = line.split(" ")
        kind = f[0]
        if kind == "p7":
            name = f[1]
            kv = dict(x.split("=", 1) for x in f[2:] if "=" in x)
            blocks[name] = {"kv": kv, "md_algs": [], "certs": {},
                            "signers": {}}
        elif kind == "p7bad":
            blocks[f[1]] = None
        elif kind == "p7digestalg":
            blocks[f[1]]["md_algs"].append(f[2])
        elif kind in ("cert", "signer"):
            kv = dict(x.split("=", 1) for x in f[3:] if "=" in x)
            key = "certs" if kind == "cert" else "signers"
            blocks[f[1]].setdefault(key, {}).setdefault(int(f[2]), {}).update(kv)
        elif kind in ("certissuer", "certsubject", "certnotbefore",
                      "certnotafter", "certfp"):
            rest = line.split(" ", 3)[3]
            blocks[f[1]]["certs"].setdefault(int(f[2]), {})[kind] = rest
        elif kind == "chain":
            blocks[f[1]]["signers"].setdefault(int(f[2]), {}) \
                .setdefault("chain", []).append(line.split(" ", 4)[4])
        elif kind == "chainlen":
            kv = dict(x.split("=", 1) for x in f[4:] if "=" in x)
            blocks[f[1]]["signers"].setdefault(int(f[2]), {})["root"] = \
                kv.get("root")
        elif kind == "signerissuer":
            rest = line.split(" ", 3)[3]
            blocks[f[1]]["signers"].setdefault(int(f[2]), {})[kind] = rest
        elif kind == "authattr":
            blocks[f[1]]["signers"].setdefault(int(f[2]), {}) \
                .setdefault("auth", []).append(f[3])
    return blocks


def chain_from(certs, issuer, serial):
    """Leaf-first chain over openssl's printed subjects and issuers."""
    by_subject = {}
    for c in certs:
        by_subject.setdefault(c.get("subject"), c)
    cur = None
    for c in certs:
        if c.get("issuer") == issuer and c.get("serialNumber") == serial:
            cur = c
            break
    out = []
    seen = set()
    while cur is not None and cur.get("subject") not in seen:
        out.append(cur.get("subject"))
        seen.add(cur.get("subject"))
        if cur.get("issuer") == cur.get("subject"):
            break
        cur = by_subject.get(cur.get("issuer"))
    return out


def last_issuer(certs, subject):
    """The issuer of the certificate with this subject, or None."""
    for c in certs:
        if c.get("subject") == subject:
            return c.get("issuer")
    return None


def cmp1(tag, what, mine, theirs):
    if str(mine) == str(theirs):
        ok("%s %s %s" % (tag, what, mine))
    else:
        bad("%s %s: jarv %r openssl %r" % (tag, what, mine, theirs))


def check(jarv, work, jar):
    tag = jar.rsplit("/", 1)[-1]
    rc, jt = run([jarv, "--pkcs7", jar])
    blocks = parse_jarv(jt)
    for name, ours in blocks.items():
        path = os.path.join(work, tag + "." + name.replace("/", "_"))
        rc, raw = runb(["unzip", "-p", jar, name])
        if rc != 0 or not raw:
            d = os.path.join(work, "x")
            subprocess.run(["rm", "-rf", d])
            os.makedirs(d, exist_ok=True)
            subprocess.run(["jar", "xf", os.path.abspath(jar), name], cwd=d,
                           stderr=subprocess.DEVNULL)
            raw = open(os.path.join(d, name), "rb").read()
        open(path, "wb").write(raw)
        rc, ot = run(["openssl", "pkcs7", "-print", "-inform", "DER",
                      "-in", path])
        if rc != 0:
            bad("%s %s: openssl pkcs7 -print exited %d" % (tag, name, rc))
            continue
        theirs = parse_openssl(ot)
        if ours is None:
            bad("%s %s: jarv refused a block openssl read" % (tag, name))
            continue
        t = tag + " " + name
        # openssl's top-level "type" is the outer ContentInfo; jarv only
        # parses a block whose outer type is signedData, so that one is
        # asserted rather than compared. The interesting one is the
        # encapsulated content type, which openssl prints under contents.
        cmp1(t, "outertype", "1.2.840.113549.1.7.2", theirs["type"])
        cmp1(t, "contenttype", ours["kv"]["contenttype"],
             theirs["content_type"])
        cmp1(t, "version", ours["kv"]["version"], theirs["version"])
        cmp1(t, "digestalgs", ",".join(ours["md_algs"]),
             ",".join(theirs["md_algs"]))
        cmp1(t, "detached", ours["kv"]["detached"],
             "1" if theirs.get("detached") else "0")
        cmp1(t, "certcount", ours["kv"]["certs"], len(theirs["certs"]))
        cmp1(t, "signercount", ours["kv"]["signers"], len(theirs["signers"]))
        for i, oc in enumerate(theirs["certs"]):
            mc = ours["certs"].get(i)
            if mc is None:
                bad("%s cert %d missing from jarv" % (t, i))
                continue
            cmp1(t, "cert%d.version" % i, mc["version"],
                 int(oc["version"]) + 1)
            cmp1(t, "cert%d.serial" % i, mc["serial"], oc["serialNumber"])
            cmp1(t, "cert%d.sigalg" % i, mc["sigalg"], oc["algs"][0])
            cmp1(t, "cert%d.keyalg" % i, mc["keyalg"], oc["algs"][1])
            cmp1(t, "cert%d.issuer" % i, mc["certissuer"], oc["issuer"])
            cmp1(t, "cert%d.subject" % i, mc["certsubject"], oc["subject"])
            cmp1(t, "cert%d.notbefore" % i, mc["certnotbefore"],
                 oc["notBefore"])
            cmp1(t, "cert%d.notafter" % i, mc["certnotafter"], oc["notAfter"])
        for i, os_ in enumerate(theirs["signers"]):
            ms = ours["signers"].get(i)
            if ms is None:
                bad("%s signer %d missing from jarv" % (t, i))
                continue
            cmp1(t, "signer%d.version" % i, ms["version"], os_["version"])
            cmp1(t, "signer%d.issuer" % i, ms["signerissuer"], os_["issuer"])
            cmp1(t, "signer%d.serial" % i, ms["serial"], os_["serial"])
            cmp1(t, "signer%d.digestalg" % i, ms["digest"], os_["algs"][0])
            cmp1(t, "signer%d.encalg" % i, ms["enc"], os_["algs"][1])
            cmp1(t, "signer%d.authattrs" % i, ",".join(ms.get("auth", [])),
                 ",".join(os_["auth"]))
            # The chain, rebuilt here from openssl's own subject and
            # issuer strings rather than read back from jarv. The
            # SignedData certificate set is a SET and so unordered, and
            # openssl prints it in encoding order, so an ordering that
            # happened to agree with the file would prove nothing.
            want = chain_from(theirs["certs"], os_["issuer"], os_["serial"])
            cmp1(t, "signer%d.chain" % i, " -> ".join(ms.get("chain", [])),
                 " -> ".join(want))
            cmp1(t, "signer%d.chainroot" % i, ms.get("root"),
                 "1" if want and want[-1] == last_issuer(theirs["certs"],
                                                         want[-1]) else "0")


def keytool_check(jarv, jar):
    """keytool -printcert -jarfile, on the certificate fingerprints.

    A second JDK opinion, and the one fact that pins the exact bytes
    jarv pulled out of the SignedData: keytool prints the SHA-256 of
    each signer certificate, so a parse that took the right fields out
    of the wrong certificate would still fail here.
    """
    tag = jar.rsplit("/", 1)[-1]
    rc, kt = run(["keytool", "-printcert", "-jarfile", jar])
    if rc != 0:
        # keytool verifies the jar before it will print anything, so a
        # tampered archive gets a refusal rather than a certificate list.
        # Counted apart from agreement and from disagreement: an oracle
        # that declined to answer has not agreed with anything.
        global REFUSED
        REFUSED += 1
        print("refused %s keytool -printcert: %s"
              % (tag, kt.strip().splitlines()[0] if kt.strip() else "exit %d" % rc))
        return
    theirs = set()
    for line in kt.splitlines():
        line = line.strip()
        if line.startswith("SHA256:"):
            theirs.add(line.split(":", 1)[1].replace(":", "").strip().lower())
    rc, jt = run([jarv, "--pkcs7", jar])
    ours = set(l.split(" ")[3] for l in jt.splitlines()
               if l.startswith("certfp "))
    if not theirs and not ours:
        return
    if ours == theirs:
        ok("%s keytool: %d signer certificate fingerprints agree"
           % (tag, len(ours)))
    else:
        bad("%s keytool fingerprints: jarv %s, keytool %s"
            % (tag, sorted(ours), sorted(theirs)))


def main():
    jarv, work = sys.argv[1], sys.argv[2]
    for jar in sys.argv[3:]:
        check(jarv, work, jar)
        keytool_check(jarv, jar)
    print("P7CMP_REFUSED %d" % REFUSED)
    print("P7CMP_PASS %d" % PASS)
    print("P7CMP_FAIL %d" % FAIL)


main()
