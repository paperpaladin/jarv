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
 * end, and a length that is a multiple of four. A lenient decoder lets a
 * digest value carry trailing junk that changes nothing it decodes to,
 * which is a way to make two different manifest bytes mean one digest.
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
		if (n == 0 || (n & 3) != 0) {
			return null;
		}
		int pad = 0;
		while (pad < 2 && n - pad - 1 >= 0 && s.charAt(n - pad - 1) == '=') {
			pad++;
		}
		byte[] out = new byte[n / 4 * 3 - pad];
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
