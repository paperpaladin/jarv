package jarv;

/**
 * Base64 decoding, strict.
 *
 * Twenty lines, so java.util.Base64 is not worth the dependency argument,
 * and writing it buys a check: every digest value in every manifest in the
 * corpus is decoded here and compared against what coreutils base64 makes
 * of the same string.
 *
 * Strict means: no characters outside the alphabet, padding only at the
 * end, and no stray bits left over in the final group. A lenient decoder
 * lets a digest value carry junk that changes nothing it decodes to, which
 * is two spellings of one digest value in a file whose whole purpose is
 * that its bytes are pinned.
 *
 * Unpadded input is accepted, because coreutils base64 -d and
 * java.util.Base64 both accept it and refusing it would be jarv alone
 * against two implementations.
 *
 * Where jarv is deliberately stricter than each of them, measured:
 *
 *   java.util.Base64 decodes "AB==" to one zero byte. The two low bits of
 *   B are dropped. So does it for every character in that position, which
 *   makes 64 spellings of the same value. jarv refuses all but "AA==".
 *   Since jarsigner uses java.util.Base64, a manifest crafted that way
 *   verifies for jarsigner and is refused by jarv. That is a refusal and
 *   is counted as one.
 *
 *   coreutils base64 -d decodes "AA==AA==" to two zero bytes, carrying on
 *   past the padding. java.util.Base64 refuses it and so does jarv.
 */
public final class B64 {
	private B64() {
	}

	private static final int[] V = new int[128];

	static {
		for (int i = 0; i < 128; i++) {
			V[i] = -1;
		}
		String a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		for (int i = 0; i < a.length(); i++) {
			V[a.charAt(i)] = i;
		}
	}

	/** Decoded bytes, or null if the input is not strict base64. */
	public static byte[] decode(String s) {
		int n = s.length();
		if (n == 0) {
			return new byte[0];
		}
		int pad = 0;
		while (pad < 2 && n - pad - 1 >= 0 && s.charAt(n - pad - 1) == '=') {
			pad++;
		}
		int body = n - pad;
		// With padding the whole thing is a multiple of four; without it
		// the remainder may be two or three characters but never one,
		// since one character carries six bits and no whole byte.
		if (pad > 0 ? (n & 3) != 0 : (n & 3) == 1) {
			return null;
		}
		int groups = body / 4;
		int tail = body - groups * 4;
		int outLen = groups * 3 + (tail == 0 ? 0 : tail - 1);
		byte[] out = new byte[outLen];
		int o = 0;
		int acc = 0;
		int bits = 0;
		for (int i = 0; i < n - pad; i++) {
			char c = s.charAt(i);
			if (c >= 128 || V[c] < 0) {
				return null;
			}
			acc = (acc << 6) | V[c];
			bits += 6;
			if (bits >= 8) {
				bits -= 8;
				if (o >= out.length) {
					return null;
				}
				out[o++] = (byte) (acc >> bits);
			}
		}
		if (o != out.length) {
			return null;
		}
		// Whatever is left in the accumulator came from the padded group
		// and must be zero. "AA==" decodes to one zero byte; "AB==" has a
		// non-zero remainder and is two spellings of the same byte.
		if ((acc & ((1 << bits) - 1)) != 0) {
			return null;
		}
		return out;
	}
}
