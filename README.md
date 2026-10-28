# jarv

A JAR signature verifier written from scratch in Java. Its own zip reader,
its own manifest parser, its own DER decoder, its own PKCS#7 reader, its own
RSA and ECDSA verification. It calls into the platform for two things and
says so below.

It exists for the part of JAR signing that is not signing. A signature
covers the entries the manifest lists. An entry that is in the archive and
not in the manifest is covered by nothing, extracts like any other member,
and tooling has been quiet about it for a long time: `jarsigner -verify`
over such an archive prints `jar verified.`, exits 0, and mentions the
uncovered members in a warning paragraph further down. jarv prints the same
verdict, because disagreeing with `jarsigner` is this project's definition of
failure, and then prints a line per uncovered entry above the summary.

```
$ jarv --verify added.jar
jar verified
signer 0 sf=META-INF/RSA1.SF block=META-INF/RSA1.RSA sig=ok link=manifest ...
UNSIGNED smuggled.txt is in the archive and in no manifest section
summary entries=21 signable=15 signed=14 partial=0 unsigned=1 uncovered=0 ...
```

Four ways a member can fail to be covered, counted and printed apart because
they are four different statements. UNSIGNED is in the archive and in no
manifest section. UNCOVERED is in the manifest with no working signer behind
it. MISMATCH is in the manifest and digests to something else. PARTIAL is
covered by some signers and not others.

## Building and running

```sh
make            # plain javac, no build system, no dependency
make test       # builds the corpus and runs every comparison
make mutants    # the mutation harness
./jarv --verify FILE.jar
```

Modes: `--zip`, `--manifest`, `--digest`, `--digests`, `--der`, `--pkcs7`,
`--sig`, `--b64`, `--curves`, `--entries`, `--verify`. Everything but the
last two is there so an outside tool can be asked the same question.

Exit codes: 0 verified, 1 unsigned, 2 rejected, 3 refused, 4 unusable input.
A refusal is never a rejection and the two never share a code.

`JARV_NOW` overrides the clock certificate validity is judged against, in
seconds since the epoch.

## The oracles

Nothing in the suite is checked against jarv's own output.

`openssl asn1parse` and `openssl pkcs7 -print` for the signature block,
node by node and field by field. Different vendor, different decade, no
shared code with the JDK. `openssl pkeyutl -verifyrecover` for what an RSA
signature decrypts to, which is the one question that reaches the padding
and the modular exponentiation without involving a digest or any content.
`openssl dgst -verify` for whether the bytes jarv nominates as signed are
the bytes the signature covers. `openssl ecparam -param_enc explicit` for
the curve constants. `openssl x509` and `openssl pkcs12` where a
certificate or a key has to come out of something.

`unzip -l` and `zipinfo -v`, Info-ZIP, for the container. Also unrelated to
the JDK.

`sha1sum`, `sha256sum`, `sha384sum`, `sha512sum` and `base64` from
coreutils, and python3's `hashlib` and `zipfile` inside the comparison
scripts, for digests and for reading archives without jarv.

`jarsigner -verify -verbose` and `keytool -printcert -jarfile`. Same vendor
as the library being replaced, so the weakest in principle, and the only one
that knows what a JAR signature means. Its verdict is the headline number
because nothing else produces one. This line used to say `-certs` as well.
It never did: `-certs` adds a certificate dump under each entry and nothing
here reads it, because `keytool -printcert -jarfile` is the certificate
oracle and `openssl pkcs7 -print` is the one behind that.

`java.util.zip.ZipFile` through a 55-line helper, as a second opinion on the
container only, and `java.util.jar.Manifest` through another as a second
opinion on the manifest. Both ship with `jarsigner`, so they are named here
to keep them from being mistaken for independent authorities. The manifest
one is the parser `jarsigner` writes manifests with, which makes it the
authority on what a 72-byte fold joins back to, and it is asked nothing
about signatures.

Python's own RSA arithmetic, `pow(m, d, n)` over the modulus and private
exponent that `openssl rsa -text` prints, for crafting signatures over
chosen encoded messages. `openssl pkeyutl` refuses a 256-byte input to
`-sign` with `rsa_padding_mode:none` and `rsautl -raw` is deprecated, so
doing the arithmetic directly was the shorter path and it also keeps the
crafting out of the openssl code that then judges the result.

## The numbers

Measured by `make test` on 21 October 2026. Every number below is a line the
suite printed, wrapped to fit.

```
ok   container: 5459 facts agree with Info-ZIP, 0 disagree
ok   container, second opinion: 2657 facts agree with java.util.zip.ZipFile,
     0 disagree, 1 refused
ok   base64: 149 strings, 29 accepted and 120 rejected by both
ok   base64: 37 of 149 agree with java.util.Base64, 112 refused by jarv and
     accepted by it, 0 the other way
ok   manifest, second opinion: 908 facts agree with java.util.jar.Manifest,
     0 disagree, 1 refused
ok   manifest: 811 facts agree, 0 disagree
ok   DER: 2985 node facts agree with openssl asn1parse, 0 disagree
ok   DER cases: 13 agree with openssl asn1parse, 7 refused by jarv as BER
     and accepted by openssl
ok   PKCS7: 651 facts agree with openssl and keytool, 0 disagree,
     3 refused by the oracle
ok   curves: 21 constants agree with openssl ecparam, 0 disagree
ok   signatures: 149 facts agree with openssl, 0 disagree, 2 refused
ok   jarsigner: 955 facts agree, 0 disagree, 11 refused
ok   encoded messages: 30 agree with jarsigner, 0 disagree
ok   corruption: 64 agree, 0 disagree, 83 both declined,
     28 one declined (11 jarv, 17 jarsigner), 0 crashes

14997 passed, 0 failed
```

The headline is the `jarsigner` line: 955 facts over 26 archives, zero
disagreements in either direction, which is the invariant in PLAN.md. What
those 955 are:

- 849 per-entry flags, three for each of 283 members. `jarsigner -verbose`
  prints a flag column per member, and the three letters that mean anything
  without a keystore are compared one at a time: `m` for listed in the
  manifest, `s` for a signature verified, `?` for unsigned.
- 23 archive verdicts. 19 both accept, 3 both reject, and `unsigned.jar`
  which both call unsigned. The count matters in both directions: an
  archive jarv accepts and `jarsigner` rejects is a failure, and so is the
  reverse, whichever of the two is right about the specification.
- 23 exit codes, each checked against jarv's own printed verdict rather
  than against `jarsigner`, since nothing outside jarv defines them.
- 22 comparisons of whether there are members nothing signed. This is the
  warning paragraph `jarsigner` prints under `jar verified.`, and it is the
  thing the project was written for.
- 38 certificate flags, expiry and self-signing, over the 19 archives where
  `jarsigner` got far enough to print them. One certificate in the corpus
  has expired and one chain is not self-signed; the other 18 of each pair
  are the ordinary answer and `jarsigner` agrees on all 38.

Refusals are counted apart from agreements everywhere, and a refusal is
never scored as agreement with anybody. The ones in the run above:

- 11 in the `jarsigner` comparison. Four archives are rejected before
  `jarsigner` prints the warning paragraph the expiry and self-signing flags
  come from, so there is nothing to compare those against. Three of those
  four also get no per-entry listing, because it raises a SecurityException
  partway through. One is `zip64-dd.jar`, which it will not open at all. One
  is `dsa.jar`, which jarv refuses by design. One is `sha1.jar`, where the
  two tools disagree about the word rather than the outcome. And one counts
  the 123 entries that are the manifest, the signature files, the signature
  blocks and the directories, which `jarsigner` flags by a rule about the
  JarFile API rather than about a digest.
- 7 in the DER cases: BER encodings that `openssl asn1parse` accepts and
  jarv refuses, listed under what does not work below.
- 3 in the PKCS#7 comparison: `keytool -printcert -jarfile` checks digests
  before it will print a certificate, so it declines on the three archives
  with a broken digest or signature.
- 2 in the signature comparison: `dsa.jar`, and `decoy.jar` which python3's
  `zipfile` will not open because of the decoy end records.
- 1 in the second container opinion: `zip64-dd.jar` again, which
  `java.util.zip.ZipFile` reads and `jarsigner` does not.
- 1 in the second manifest opinion: `decoy.jar`, whose manifest the probe
  never sees, because python3's `zipfile` finds a decoy end record and will
  not open the archive to hand it over.
- 112 base64 strings jarv refuses and `java.util.Base64` accepts, all of
  them crafted, none of them in any archive.

## What the corpus holds

Built at suite run time into a `mktemp -d` by `t/corpus.sh`, from `keytool`,
`jar`, `jarsigner` and `t/mkzip.py`. No key material is committed. The
keystore, four RSA keys, three EC keys and one DSA key are generated fresh
on every run, with a password read from `/dev/urandom`, and the directory is
deleted when the suite ends.

Counted by `t/constructs.py` with python3's `zipfile`, a raw byte scan and
`openssl`, never by jarv, so a construct jarv cannot see reads as zero here
and turns the suite red. The suite refuses to run if any of these is absent.

Two of the numbers do not add up at first reading and both are correct.
There are 26 archives and 25 manifests, because python3's `zipfile` is
fooled by the decoy end records and will not open `decoy.jar`, so nothing
inside it is counted; the counts that come from the raw byte scan, archives
and signature blocks among them, do include it. And there are 27 signature
files to 26 blocks, because `metainf.jar` carries a `.SF` with no block
beside it on purpose.

```
archives             26     fold_continuation    443
entries             505     fold_space_after_marker 24
zip64_eocd            3     fold_splits_utf8      24
zip64_extra          80     decoy_end_record       1
data_descriptor     325     rsa_block             22
no_data_descriptor  180     ec_block               3
stored              132     dsa_block              1
deflated            373     curve_p256             1
empty_entry          25     curve_p384             1
directory            75     curve_p521             1
archive_comment       2     multi_cert_block       1
utf8_flag           505     issuer_differs_from_subject 1
non_ascii_name       50     two_signature_files    3
name_over_72        125     covered_by_one_sf_only 15
name_exactly_72      25     stale_manifest_digest  2
signature_block      26     sha1_entry_digest      1
signature_file       27     manifest              25
```

The archives, and what each is for:

- `good-rsa`, `good-ec`, `good-sha512`, `ec384`, `ec521`: correctly signed,
  across RSA with three digest sizes and ECDSA on all three NIST prime
  curves.
- `chain`: signed by a leaf that a CA in the same keystore issued, so one
  certificate in the corpus has an issuer that differs from its subject and
  one signature block carries two certificates.
- `tampered`, `bitflip`: one entry edited after signing, by replacement and
  by one flipped bit.
- `sigflip`: one bit flipped in the last byte of the signature block, which
  is the last byte of the encrypted digest.
- `added`: an entry added after signing and absent from the manifest. The
  headline case.
- `partial`: signed, an entry added, signed again by a second signer. The
  new entry is covered by one of two signers, and the first signer's
  whole-manifest digest is stale so its `.SF` is tied to the manifest
  section by section instead.
- `dropped`: an entry removed from the archive and left in the manifest.
- `two-signers`: two signers over the same contents.
- `expired`: signed with a certificate that expired two years ago.
- `dsa`: DSA, which is a declared non-goal. `jarsigner` verifies it and jarv
  refuses it, and the suite asserts both halves.
- `sha1`: entry digests in SHA-1. `jarsigner` signs it and then reports it as
  unsigned; jarv refuses it and names the algorithm.
- `unsigned`: no signature at all.
- `zip64`, `zip64-store`, `zip64-partial`, `zip64-dd`: zip64 end records,
  with the extended information extra field full and sparse, with stored
  entries, and with data descriptors.
- `stored`, `nodd`, `comment`: stored rather than deflated, no data
  descriptors, and an archive comment after the end of central directory
  record.
- `decoy`: two more things that look like an end of central directory
  record, one inside a stored entry before the real one and one in the
  archive comment after it.
- `metainf`: a `.SF` one level too deep in `META-INF`, which is an ordinary
  member, and one whose directory differs only in case, which is signature
  machinery. Both tools classify both the same way and both name both.

Manifest constructs are built deliberately rather than hoped for. Entry
names are chosen so that a `Name: ` line lands at 62, 65, 66, 67, 68 and 72
bytes, which puts the 72-byte fold on each side of the boundary and exactly
on it. One name has a space at the fold, so the continuation line begins
with two spaces and a reader that strips whitespace rather than exactly one
character loses one. One name is 67 bytes of UTF-8 whose fold lands inside a
three-byte character, which a reader that decodes each physical line before
joining cannot reassemble.

## What does not work

Certificate signatures are not verified. jarv builds the chain, orders
it leaf first by matching the DER of each issuer name against a subject
name, finds the self-issued root, and reads the validity dates. It does not
check that the issuer actually signed the subject. `jarsigner` with no
keystore does not either, and prints a warning saying the chain could not be
validated, which the suite compares. A verifier that built chains and never
checked them would be worth nothing against an attacker who can add a
certificate to the block, and jarv is in that position today.

Timestamps are reported and not checked. An RFC 3161 token in the
unauthenticated attributes is counted and its presence printed. Nothing
reads it. This means jarv cannot tell a signature made before a certificate
expired from one made after. The reporting half has never been seen to say
yes, either: every signer in the corpus prints `timestamped=0`, because
`jarsigner -tsa` wants a timestamp authority over the network and nothing
here reaches one. So the flag is a line of output with no case behind it,
which is a weaker claim than the rest of this README makes.

There is no revocation checking: no CRL, no OCSP.

DSA is refused rather than verified. That is deliberate and it is asserted:
the corpus has a DSA archive, `jarsigner` verifies it, and jarv is required
to refuse it cleanly and be counted as having refused.

Five mutants survive. Each is a rule in the code that nothing in the
corpus can make fail, and each is here with the reason rather than with a
plan to get to it.

How those were measured is worth stating, because the number would mean
something different otherwise. `t/mutants.py` holds 47 single-edit mutants
and runs the whole suite against each. Every mutant added while this was
being built was run individually at the time it was written, against the
suite as it stood, and the five below are the ones that did not die.

Two counts in this paragraph said 57 until the table was counted rather
than recalled. They had been written when the table was that size and never
revisited as entries were merged, which is the same drift that makes a
mutation score worth less than it looks: the number is about a table, and a
table changes. `make test` now runs `t/mutants.py --check`, which asks only
whether every pattern still appears exactly once in the file it names, and
goes red on a refactor.

A
single sweep of all 47 in one sitting has not been completed: the suite is
three and a half minutes and this machine was running two other
repositories' sweeps at the same time, which puts one pass over three
hours. What has been run end to end is the manifest group, reported below.
Anything claiming to be a survivor has been run against the full suite with
nothing skipped.

- The ECDSA digest truncated by byte length rather than by bit length. Over
  the three curves and the five SHA digests in use the two never differ.
  P-521 is the only curve whose order is not a whole number of bytes and no
  digest reaches its 66, so nothing is truncated on it at all.
- `r` compared with `x1` rather than with `x1 mod n`. They differ only when
  `x1` is at least `n`, and `x1` is bounded by `p`. For P-256 the gap is
  about one part in 2^32 and for P-521 about one in 2^262.
- An RSA signature at or above the modulus reduced rather than refused. The
  value would have to fit in the same number of bytes as the modulus, which
  `s + n` does only when `s` happens to be below 2^2048 minus `n`. That is a
  coin flip on a keystore generated fresh every run, and a case that is
  present half the time is worse than one that is absent.
- The eight-byte minimum on the PKCS#1 padding run. No key `jarsigner` will
  produce can violate it: with a 2048-bit modulus the run is 218 bytes for a
  SHA-1 DigestInfo and 170 for SHA-512, and even a 512-bit key leaves 10 for
  SHA-256. It would take a modulus under 500 bits.
- Chain building matched on the printed name instead of on the DER. That is
  the case the code is written against, and every name in the corpus is a
  PrintableString, so the two spellings never diverge. It would take a
  certificate carrying a UTF8String name with the same text as another's
  PrintableString, which `keytool` will not make.

Three further mutants were written and dropped before committing rather than
recorded as survivors, because each was unreachable only because a second
guard covered for it: a certificate appearing twice in one chain, not
stopping at a self-issued certificate, and an attribute carrying several
values. A survivor that exists because two guards overlap says nothing about
the suite.

The DER decoder refuses seven BER encodings openssl accepts. Indefinite
length, non-minimal long-form lengths, padded length octets and padded
object identifier arcs are each refused rather than normalised, because DER
is BER with the ambiguity removed and a signature is a claim about one
sequence of bytes. `openssl asn1parse` accepts all seven. Those are counted
as refusals, not as agreements, and nothing the JDK writes contains one.

Base64 is stricter than both of its oracles, and that costs something. A
padded group carries bits that no output byte uses, and `java.util.Base64`
ignores them rather than requiring them to be zero. `AB==` decodes to one
zero byte, as do the other fifteen spellings `Ax==` can take, and `AAx=`
gives four spellings of two zero bytes; jarv accepts only `AA==` and `AAA=`.
Both figures were counted by running the 64 alphabet characters through
`java.util.Base64` rather than worked out from the encoding, because this
README said 64 spellings for some time and the number is 16. Since
`jarsigner` uses `java.util.Base64`, a manifest crafted that way verifies
for `jarsigner` and is refused by jarv. 112 of 149 probe strings are refused
by jarv and accepted by the JDK for that reason. They are counted as
refusals. No corpus archive contains one, so this is a difference on crafted
input only.

The suite's total is stable and the per-column numbers in the corruption
sweep are not. The keys cannot be fixed, because nothing here may commit
one, so which column a corrupted archive lands in moves a little from run
to run. The sweep is 35 cases over each of five archives, 175 in all: 11
truncations, 12 single-bit flips and 12 sixteen-byte holes, every offset a
twelfth of the file rather than a step of a fixed size. So the number of
cases does not depend on how big this run's keys made the archive, and
every case counts as one assertion whichever column it lands in. Both of
those were defects before they were properties, and both produced a green
suite whose number was not reproducible.

`java.util.zip` is used for two things: `Inflater` for method 8 and
`CRC32` for the check. Writing a deflate decoder was not the point of this
project and there is one in the collection already; writing the container
parse was the point and the container parse is jarv's own. `MessageDigest`
is the other platform call: SHA-2 is not reimplemented here either.

One `BigInteger` dependency matters. `modPow` does the RSA
operation and `modInverse` does the ECDSA one. The padding, the DigestInfo,
the curve arithmetic and the point decoding are all written out, because
those are where verifiers go wrong, but the modular exponentiation itself
is the platform's.

ECDSA point arithmetic is affine, with a modular inverse per addition
and per doubling. That is the slow way. The whole suite spends well under a
second in it and Jacobian coordinates would add a page of code whose bugs
produce wrong answers rather than slow ones. Marked in the source with the
ceiling and the upgrade path.

A signer identified by subject key identifier is refused. Resolving one
means indexing certificates by their key identifier extension, which jarv
does not do. Nothing the JDK produces uses that form.

A block with more than one SignerInfo is refused. Several signers behind
one `.SF` would leave the coverage table unable to say which signer a given
entry belongs to.

## Defects found in the harness, not in the code

Recorded because they are the ones that nearly got away, and because in this
collection most defects have been in the harness.

The suite was structurally unable to see a verifier that stops verifying.
Deleting the unused-bits handling in `bitString` made every RSA public key
unparseable, so every signature became a refusal, and refusals were being
counted apart from failures exactly as planned. The run stayed green. A
refusal is only honest for something jarv says it does not do, and RSA is
not on that list; a refusal on an RSA or EC signature is a disagreement now,
and the same mutation gives 16 failures.

Two overlapping rules were covered by one case. Digest algorithm parameters
must be NULL, and that NULL must be empty. The crafted case fed them an
INTEGER, which is neither, so deleting either rule left the other to reject
it and the mutation of the first survived. Each rule has a case only it can
reject now, and the second rule had no mutant at all before.

A harness that reads only accept-or-reject scores a crash as a correct
rejection. With the ECDSA range check deleted, `modInverse` throws on a zero
`s`, jarv prints no verdict line, and a reader of yes-or-no counts the
missing line as a no. Every crafted case asserts the verdict text now.

A two-certificate chain was counted as one certificate. `p7cmp.py` split
`openssl pkcs7 -print` on the string `cert:`, and openssl prints that header
once and a `cert_info:` block per certificate. Every archive had exactly one
certificate until `chain.jar`, so the splitter had never been asked a
question it could get wrong.

A question that cannot be asked was asked anyway. `sigcmp.py` requires
`openssl dgst -verify` to accept the bytes jarv nominates as signed, which
is meaningless for an archive whose signature is deliberately broken: the
rejection has two causes and they are indistinguishable from outside. It
reported that jarv had the signed bytes wrong for `sigflip.jar`.

Three warnings were compared against archives where the oracle never printed
them. `jarsigner` prints its warning paragraph only after deciding a jar
verifies, so for a rejected archive there is nothing to compare the expiry
and self-signing flags against. jarv was right in all three cases and the
harness was wrong to call them disagreements.

The expected disagreement was not the one that existed. `jdkzip.py` was
written to assert that `java.util.zip.ZipFile` refuses at least one archive,
on the strength of `jarsigner` refusing `zip64-dd.jar`. `ZipFile` opens all
of them. The refusal lives in the streaming reader `jarsigner` uses, not in
the random-access one, so the two halves of one library answer differently
about the same file.

The suite total was not reproducible, twice, for two reasons one commit
apart. First the corruption sweep counted only the cases where both tools
judged and agreed, so a case moving between columns took a point with it,
and which column a case lands in depends on bytes of a key generated fresh
every run. Then, with the counting fixed, the offsets themselves were taken
by stepping a stride of `len/12` through each archive, which gives twelve
points for one length and thirteen for another. The shape is worth naming
rather than the instance: any count derived from a stride over data whose
length is not fixed is a count that moves.

## Defects found in jarv

jarv refused an archive `jarsigner` verifies. An unparsable signature file
with no block beside it made a signer jarv could not use, and the whole
archive was refused on the strength of it. `jarsigner` is right: a stray
signature file covers nothing, and refusing an archive whose real signature
is intact because of an entry that claims nothing is the wrong answer. A
signer refusal refuses the archive only when no signer works at all.

48 rejections were reported as refusals. An entry the container will not
decompress is an entry whose digest cannot be shown to hold while the
manifest says it should, which is an answer rather than a declining to
answer. The corruption sweep went from 20 agreements to 68 when that was
corrected.

The P-521 group order was wrong. Fourteen extra `ff` bytes, 160 hex digits
where the standard has 132, typed in by hand and read by nothing that could
tell. Every P-521 signature would have been rejected. It surfaced only
because the corpus grew an archive on that curve, and the answer was to give
the curve table an oracle of its own: all six constants per curve against
`openssl ecparam`, plus a check that the generator satisfies the curve
equation, which is the other five held against each other.

A comment in `Ec.java` claimed that truncating a digest by byte length
rather than by bit length would reject valid P-521 signatures. It would not.
Over the three curves and the five SHA digests in use the two truncations
never differ, because P-521 is the only curve whose order is not a whole
number of bytes and no digest reaches its 66. The comment was written from
the shape of the rule rather than from the arithmetic.

## Reproducibility

Every commit builds, and that is measured rather than assumed. `cq b jarv`
creates a fresh git worktree per commit, reads the Makefile as it was at
that commit and builds the default target there. The last full run was 40
of 40, taken at the commit before this paragraph was written.

## Layout

```
src/jarv/     4047 lines of Java, 17 files, no dependency
t/            4459 lines of harness, python3 and three short Java probes
t/corpus.sh   builds the corpus from keytool, jar, jarsigner and mkzip.py
t/mutants.py  the mutation harness
```

`Zip.java` and `Zip64.java` are the container, `Manifest.java` the manifest
grammar with byte ranges, `Der.java` the decoder, `Pkcs7.java` and
`X509.java` the signature block, `Rsa.java` and `Ec.java` the arithmetic,
`Verify.java` the verdict.
