package jarv;

/** Lower-case hex, because every oracle this project talks to prints that. */
public final class Hex {
	private Hex() {
	}

	private static final char[] D = "0123456789abcdef".toCharArray();

	public static String of(byte[] b) {
		char[] c = new char[b.length * 2];
		for (int i = 0; i < b.length; i++) {
			c[i * 2] = D[(b[i] >> 4) & 0xf];
			c[i * 2 + 1] = D[b[i] & 0xf];
		}
		return new String(c);
	}

	public static byte[] parse(String s) {
		if ((s.length() & 1) != 0) {
			return null;
		}
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hi = Character.digit(s.charAt(i * 2), 16);
			int lo = Character.digit(s.charAt(i * 2 + 1), 16);
			if (hi < 0 || lo < 0) {
				return null;
			}
			b[i] = (byte) ((hi << 4) | lo);
		}
		return b;
	}
}
