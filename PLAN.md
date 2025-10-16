# jarv

A JAR signature verifier written from scratch in Java: its own zip reader, its
own manifest parser, its own DER decoder, its own PKCS#7 reader, its own
RSA and ECDSA verification.

## Contract

Given a `.jar` file, say for every entry in the archive which signers cover it
and which do not, and give a verdict on the archive as a whole. Be explicit
about the entries that nothing covers, because that is the part signing does
not do and the part tools have historically been quiet about.

## Hard invariant

Every accept and every reject agrees with `jarsigner -verify`, per entry and
per archive, or is reported as a refusal. A refusal is never counted as an
agreement.

If jarv says an archive verifies and `jarsigner` says it does not, the project
has failed, whichever of the two is right about the specification.

## Oracle

Ranked by how little we control them.

1. `openssl asn1parse`, `openssl pkcs7 -print`. Different vendor, different
   decade, no shared code with the JDK. The authority on the signature block.
2. `unzip -l`, `zipinfo -v`. Info-ZIP, also unrelated to the JDK. The
   authority on the container.
3. `sha256sum`, `sha1sum`, `sha512sum` from coreutils. The authority on a
   digest.
4. `jarsigner -verify -verbose -certs` and `keytool -printcert`. Same vendor
   as the library we are replacing, so the weakest of the four in principle,
   and the only one that knows what a JAR signature means. Its verdict is the
   headline number anyway because nothing else gives one.
5. `java.util.zip.ZipFile` read through a tiny helper, as a second opinion on
   the container only. Named here so it is not mistaken for an independent
   authority: it ships with jarsigner.

## Non-goals

- Signing. jarv only verifies.
- Timestamps (`SignedData` unauthenticated attributes carrying an RFC 3161
  token). Reported as present and not checked.
- Revocation: no CRL, no OCSP.
- DSA signatures. `.DSA` blocks are parsed and then refused at the verify
  step, counted as refusals.
- A general-purpose zip extractor. jarv reads what a signature depends on.

## Commit sequence

- [ ] repository skeleton: Makefile, launcher, licence, plan
  why: `cq c` needs a buildable tree and a suite before anything else.
- [ ] byte cursor with bounds checking and a sticky error flag
  why: every later parser reads through it, so it goes in before them.
- [ ] end of central directory record, located by backward scan
  why: the only fixed point in a zip file is its last 22 bytes.
- [ ] central directory entries
  why: names, sizes, CRCs and local header offsets come from here.
- [ ] local file headers, checked against the central directory
  why: the two copies disagreeing is a container attack in itself.
- [ ] zip64 end of central directory locator and record
  why: a 16-bit entry count and 32-bit offsets run out, and the fallback
  path is where readers go wrong.
- [ ] zip64 extended information extra field in the central directory
  why: sizes move into the extra field one at a time, in a fixed order,
  and only the ones that overflowed are present.
- [ ] data descriptors after streamed entries
  why: a streamed entry carries zeroes in its local header and the real
  sizes afterwards.
- [ ] `--zip` listing, compared with `unzip -l` and `zipinfo -v`
  why: the container parse is worth nothing until something outside agrees.
- [ ] entry decompression and CRC check through java.util.zip.Inflater
  why: digests are over uncompressed bytes, and the CRC is a free check that
  we decompressed the right thing.
- [ ] corpus builder: a correctly signed RSA jar
  why: the first oracle run needs something to run against.
- [ ] manifest line reader: CR, LF and CRLF, continuation lines
  why: three terminators and a one-space continuation marker, and getting
  the continuation wrong is silent.
- [ ] manifest sections with exact byte ranges
  why: the signature file digests manifest section bytes, not parsed values,
  so the byte range is the thing that has to be right.
- [ ] folding at exactly 72 bytes, including a fold inside a UTF-8 sequence
  why: the documented limit is bytes, so a reader that decodes before
  joining corrupts any value folded mid-character.
- [ ] per-entry digest verification against the manifest
  why: this is what "the entry is signed" means at the bottom.
- [ ] `.SF` parsing and the `x-Digest-Manifest` whole-file shortcut
  why: the fast path, and the one that decides whether per-section digests
  are consulted at all.
- [ ] `x-Digest-Manifest-Main-Attributes`
  why: the fallback when the manifest has been added to since signing.
- [ ] per-section `x-Digest` in the `.SF`, both with and without the
  trailing blank line
  why: the JDK digests the section including its blank line and keeps a
  workaround path that excludes it. Both appear in the wild.
- [ ] DER decoder: tags, lengths, constructed nesting, object identifiers
  why: the signature block is DER and nothing else will read it for us.
- [ ] `--der` dump compared with `openssl asn1parse` offset by offset
  why: an ASN.1 decoder that is only read by its own caller is unchecked.
- [ ] PKCS#7 ContentInfo and SignedData
  why: the outer structure that holds the certificates and the signers.
- [ ] certificates out of the SignedData, counted against `openssl pkcs7`
  why: a chain of the wrong length is a verification that proved less than
  it claimed.
- [ ] X.509 parse: serial, issuer, subject, validity, public key
  why: needed for chain building and for the expiry case.
- [ ] RSA PKCS#1 v1.5 verification with BigInteger
  why: the whole point is not to call a library for the step that matters.
- [ ] DigestInfo unwrapping, with a strict length check on the padding
  why: a lax PKCS#1 unpad is the Bleichenbacher signature forgery.
- [ ] ECDSA verification over the NIST prime curves
  why: `jarsigner -sigalg SHA256withECDSA` is ordinary now.
- [ ] authenticated attributes: the signature covers the attribute set,
  not the content, when they are present
  why: getting this backwards verifies the wrong bytes and still says yes.
- [ ] `messageDigest` and `contentType` authenticated attributes checked
  why: without them the attribute set is signed and unconnected to the file.
- [ ] certificate chain ordering and self-signed root detection
  why: the SignedData certificate set is unordered.
- [ ] certificate validity dates, and the expired-certificate case
  why: an expired signer is a different verdict from a broken one.
- [ ] per-entry coverage table: which signers cover which entries
  why: the output the whole program exists to produce.
- [ ] unsigned and partially signed entries reported loudly
  why: an entry in the archive and not in the manifest is the gap.
- [ ] overall verdict and exit codes, refusal separated from rejection
  why: a verifier that refuses an input has not disagreed with anything.
- [ ] corpus: signed then tampered
  why: the simplest reject, and the one every verifier gets right.
- [ ] corpus: entry added after signing, absent from the manifest
  why: the headline case. Both tools must be asked what they think.
- [ ] corpus: two signers
  why: coverage becomes a set per entry rather than a boolean.
- [ ] corpus: expired certificate
  why: a reject for a reason that is not a digest.
- [ ] corpus: UTF-8 entry name
  why: general purpose bit 11, and a manifest name that needs folding.
- [ ] corpus: zip64 archive, signed
  why: the construct count must be non-zero or the zip64 code is untested.
- [ ] corpus: streamed entries with data descriptors
  why: the `jar` tool will not produce one, so it has to be built by hand.
- [ ] construct counter printed by the suite
  why: a zip64 test on a corpus with no zip64 archive passes vacuously.
- [ ] per-entry agreement harness against `jarsigner -verbose`
  why: comparing one verdict per jar over ten jars is ten comparisons;
  comparing flags per entry is hundreds.
- [ ] `keytool -printcert -jarfile` compared signer by signer
  why: a second JDK opinion on the certificates, independent of the
  verdict path.
- [ ] mutation harness with survivors recorded
  why: an assertion nobody has watched fail is not an assertion.
- [ ] truncation and corruption sweep over the corpus
  why: a verifier reads attacker-controlled bytes by definition.
- [ ] README with the measured numbers and what does not work
  why: a README listing only successes is not finished.
