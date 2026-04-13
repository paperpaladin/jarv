#!/usr/bin/env python3
"""Mutation harness.

Each mutant is one textual edit to one source file that changes behaviour
in a way a correct verifier would notice. The suite is run against it and
must go red. A mutant the suite does not kill is printed as a SURVIVOR and
is written down in the README rather than quietly dropped, because the
survivors are the honest measure of what the suite does not cover.

Run with: make mutants
"""
import os
import re
import signal
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (label, file, before, after)
MUTANTS = [
    ("zip: swap the two central directory size fields", "Zip.java",
     "e.compSize = b.u32();\n			e.uncompSize = b.u32();",
     "e.uncompSize = b.u32();\n			e.compSize = b.u32();"),
    ("zip: data offset one byte late", "Zip.java",
     "e.dataOff = e.localOff + b.pos();",
     "e.dataOff = e.localOff + b.pos() + 1;"),
    ("zip: take the first end record found, not the last", "Zip.java",
     "for (int i = start; i >= stop; i--) {",
     "for (int i = stop; i <= start; i++) {"),
    ("zip: accept an end record whose comment length does not reach the end",
     "Zip.java",
     "if (i + 22 + clen != file.length) {\n					continue;\n				}",
     "if (false) {\n					continue;\n				}"),
    ("zip64: ignore the zip64 end record entirely", "Zip.java",
     "		if (!bad()) {\n			findZip64Eocd();\n		}", "		if (false) {\n			findZip64Eocd();\n		}"),
    ("zip64: read the central extra field unconditionally, not sparsely",
     "Zip64.java",
     "if (e.uncompSize == MAX32) {", "if (true) {"),
    ("zip64: local extra field read as the sparse central one", "Zip64.java",
     "			if (id == ID && len >= 16) {\n				Buf b = new Buf(ex, p, len);\n				e.localUncompSize = b.u64();\n				e.localCompSize = b.u64();",
     "			if (id == ID && len >= 16) {\n				Buf b = new Buf(ex, p, len);\n				e.localCompSize = b.u64();\n				e.localUncompSize = b.u64();"),
    ("manifest: section digest stops before the blank line", "Manifest.java",
     "				s.endWithBlank = next;", "				s.endWithBlank = lineStart;"),
    ("manifest: continuation strips all leading spaces, not one",
     "Manifest.java",
     "				System.arraycopy(l, 1, joined, prev.length, l.length - 1);",
     "				int k = 0;\n				while (k < l.length && l[k] == ' ') {\n					k++;\n				}\n				joined = new byte[prev.length + l.length - k];\n				System.arraycopy(prev, 0, joined, 0, prev.length);\n				System.arraycopy(l, k, joined, prev.length, l.length - k);"),
    ("manifest: continuation keeps the marker space", "Manifest.java",
     "				System.arraycopy(l, 1, joined, prev.length, l.length - 1);",
     "				System.arraycopy(l, 0, joined, prev.length, l.length - 1);"),
    ("manifest: decode each physical line before joining", "Manifest.java",
     "		for (int n = 0; n < lines.size(); n++) {\n			byte[] l = lines.get(n);\n			if (l.length > 0 && l[0] == ' ') {",
     "		for (int n = 0; n < lines.size(); n++) {\n			byte[] l = lines.get(n);\n			if (l.length > 0 && l[0] == ' ') {\n				l = new String(l, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8);"),
    ("manifest: CR alone does not end a line", "Manifest.java",
     "while (contentEnd < raw.length && raw[contentEnd] != '\\n'\n					&& raw[contentEnd] != '\\r') {",
     "while (contentEnd < raw.length && raw[contentEnd] != '\\n') {"),
    ("manifest: CRLF counted as two line endings", "Manifest.java",
     "				if (raw[next] == '\\r' && next + 1 < raw.length\n						&& raw[next + 1] == '\\n') {\n					next += 2;",
     "				if (false) {\n					next += 2;"),
    ("base64: accept a non-zero remainder in the padded group", "B64.java",
     "		if ((acc & ((1 << bits) - 1)) != 0) {\n			return null;\n		}", ""),
    ("der: accept BER indefinite length", "Der.java",
     'throw new DerError("indefinite length at " + p + ", which is BER"\n				+ " and not DER");',
     'length = end - q;'),
    ("der: accept a non-minimal long-form length", "Der.java",
     '			if (length < 128) {\n				throw new DerError("length " + length + " at " + p + " written"\n					+ " in the long form");\n			}', ""),
    ("der: accept a padded length", "Der.java",
     '			if ((b[q] & 0xff) == 0) {\n				throw new DerError("length at " + p + " has a leading zero"\n					+ " octet, which is not the shortest form");\n			}', ""),
    ("der: accept a padded object identifier arc", "Der.java",
     '			if (oid(n) == null) {\n				throw new DerError("malformed object identifier at " + p);\n			}', ""),
    ("der: header length one byte short", "Der.java",
     "		n.hl = q - p;", "		n.hl = q - p - 1;"),
    ("digest: do not recognise the unhyphenated SHA1 spelling", "Digest.java",
     'if (p.equals("SHA") || p.equals("SHA1") || p.equals("SHA-1")) {',
     'if (p.equals("SHA-1")) {'),
    ("x509: certificate version printed without the +1", "X509.java",
     "version = (int) integer(v.kid(0)).longValue() + 1;",
     "version = (int) integer(v.kid(0)).longValue();"),
    ("x509: notBefore and notAfter swapped", "X509.java",
     "		notBefore = time(val.kid(0));\n		notAfter = time(val.kid(1));",
     "		notBefore = time(val.kid(1));\n		notAfter = time(val.kid(0));"),
    ("x509: UTCTime two-digit years all read as 19xx", "X509.java",
     "year = yy >= 50 ? 1900 + yy : 2000 + yy;", "year = 1900 + yy;"),
    ("x509: issuer and subject swapped", "X509.java",
     "		Der.Node sub = tbs.kid(i++);\n		subjectDer = sub.encoded();\n		subject = name(sub);",
     "		Der.Node sub = tbs.kid(i++);\n		subjectDer = sub.encoded();\n		subject = issuer;\n		issuer = name(sub);"),
    ("x509: a name joined in reverse order", "X509.java",
     "				if (sb.length() > 0) {\n					sb.append(\", \");\n				}\n				sb.append(label).append('=').append(text(atv.kids.get(1)));",
     "				if (sb.length() > 0) {\n					sb.insert(0, \", \");\n				}\n				sb.insert(0, label + \"=\" + text(atv.kids.get(1)));"),
    ("x509: a bit string keeps its unused-bits octet", "X509.java",
     "		byte[] out = new byte[n.len - 1];\n		System.arraycopy(n.buf, n.contentOff() + 1, out, 0, out.length);",
     "		byte[] out = new byte[n.len];\n		System.arraycopy(n.buf, n.contentOff(), out, 0, out.length);"),
    ("x509: the two copies of the signature algorithm need not match",
     "X509.java",
     "		if (!innerOid.equals(sigAlgOid)) {", "		if (false) {"),
    ("pkcs7: signer issuer and serial read in the wrong order", "Pkcs7.java",
     "		s.issuerDer = sid.kid(0).encoded();\n		s.issuer = X509.name(sid.kid(0));\n		s.serial = X509.integer(sid.kid(1));",
     "		s.issuerDer = sid.kid(1).encoded();\n		s.issuer = X509.name(sid.kid(1));\n		s.serial = X509.integer(sid.kid(0));"),
    ("pkcs7: authenticated attributes read as unauthenticated", "Pkcs7.java",
     "			s.authAttrs = si.kid(i++);\n			readAttrs(s.authAttrs, s.auth);",
     "			s.authAttrs = si.kid(i++);\n			readAttrs(s.authAttrs, s.unauth);"),
    ("pkcs7: the outer content type is not checked for signedData",
     "Pkcs7.java",
     "		if (!OID_SIGNED_DATA.equals(outer)) {", "		if (false) {"),
    ("pkcs7: the attribute set is signed as it lies, without retagging",
     "Pkcs7.java",
     "		b[0] = 0x31;", ""),
    ("rsa: a signature at or above the modulus is reduced, not refused",
     "Rsa.java",
     "		if (s.compareTo(key.n) >= 0) {\n			return null;\n		}", ""),
    ("rsa: the padding run may be shorter than eight bytes", "Rsa.java",
     "		if (i - 2 < 8) {\n			return null;\n		}", ""),
    ("rsa: the padding run is not required to be 0xFF", "Rsa.java",
     "		while (i < em.length && (em[i] & 0xff) == 0xff) {",
     "		while (i < em.length && em[i] != 0x00) {"),
    ("rsa: the digest named in the DigestInfo is not checked against the"
     " one the signer declares", "Rsa.java",
     "		if (!named.equals(digestJca)) {", "		if (false) {"),
    ("rsa: digest algorithm parameters may be anything", "Rsa.java",
     "		if (alg.kids.size() == 2 && !alg.kid(1).is(Der.UNIVERSAL, Der.NULL)) {",
     "		if (false) {"),
    ("ec: u1 and u2 swapped", "Ec.java",
     "		Pt p = add(c, mul(c, u1, g), mul(c, u2, q));",
     "		Pt p = add(c, mul(c, u2, g), mul(c, u1, q));"),
    ("ec: the digest is truncated by byte length, not by bit length",
     "Ec.java",
     "		int excess = digest.length * 8 - c.n.bitLength();",
     "		int excess = (digest.length - (c.n.bitLength() + 7) / 8) * 8;"),
    ("ec: r is compared with x1 rather than with x1 mod n", "Ec.java",
     "		if (!p.x.mod(c.n).equals(r)) {", "		if (!p.x.equals(r)) {"),
    ("ec: the public point is not checked to be on the curve", "Ec.java",
     "		if (!onCurve(c, q)) {", "		if (false) {"),
    ("ec: r and s are not range checked", "Ec.java",
     "		if (r.signum() <= 0 || r.compareTo(c.n) >= 0\n"
     "				|| s.signum() <= 0 || s.compareTo(c.n) >= 0) {",
     "		if (false) {"),
]


def run(cmd, env=None, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)


def suite(env):
    p = run(["./t/run.sh"], env=env)
    out = p.stdout.decode("utf-8", "replace")
    m = re.search(r"^(\d+) passed, (\d+) failed$", out, re.M)
    if not m:
        return None, None, out
    return int(m.group(1)), int(m.group(2)), out


# A mutant left behind by a killed run is worse than no run at all: the
# next suite goes red for a reason that is not in any commit, and the
# obvious reading is that the code is broken. Restore on the way out
# whatever happens.
_PENDING = {}


def _restore(*_):
    for path, text in list(_PENDING.items()):
        open(path, "w").write(text)
        del _PENDING[path]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *a: (_restore(), sys.exit(130)))
    dirty = run(["git", "status", "--porcelain", "src"]).stdout.decode().strip()
    if dirty:
        print("src/ has uncommitted changes; a mutation run would hide them:")
        print(dirty)
        return 2
    env = dict(os.environ)
    corpus = env.get("JARV_CORPUS")
    tmp = None
    if not corpus:
        tmp = tempfile.mkdtemp(prefix="jarv-mutants-")
        r = run(["./t/corpus.sh", tmp])
        if r.returncode != 0:
            print(r.stdout.decode())
            return 2
        corpus = tmp
        env["JARV_CORPUS"] = corpus
    run(["make", "-s"])
    base_pass, base_fail, out = suite(env)
    if base_fail != 0:
        print("the tree is already red; fix that before mutating")
        print(out[-2000:])
        return 2
    print("baseline: %d passed, 0 failed" % base_pass)
    killed = 0
    survivors = []
    for label, fname, before, after in MUTANTS:
        if only and only not in label:
            continue
        path = os.path.join(ROOT, "src", "jarv", fname)
        orig = open(path).read()
        if before not in orig:
            print("BROKEN  %s: the pattern is not in %s" % (label, fname))
            survivors.append(label + " (pattern missing)")
            continue
        _PENDING[path] = orig
        open(path, "w").write(orig.replace(before, after, 1))
        try:
            b = run(["make", "-s"])
            if b.returncode != 0:
                print("NOBUILD %s" % label)
                survivors.append(label + " (does not compile)")
                continue
            p, f, _ = suite(env)
            if f is None:
                print("KILLED  %s (the suite refused to run)" % label)
                killed += 1
            elif f > 0:
                print("KILLED  %s (%d failed)" % (label, f))
                killed += 1
            else:
                print("SURVIVOR %s" % label)
                survivors.append(label)
        finally:
            _restore()
    run(["make", "-s"])
    n = killed + len(survivors)
    print("")
    print("%d mutants, %d killed, %d survived" % (n, killed, len(survivors)))
    for s in survivors:
        print("  survivor: " + s)
    if tmp:
        import shutil
        shutil.rmtree(tmp)
    return 0


sys.exit(main())
