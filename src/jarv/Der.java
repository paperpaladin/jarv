package jarv;

import java.util.ArrayList;
import java.util.List;

/**
 * A DER decoder.
 *
 * DER is BER with the ambiguity removed, and the removed ambiguity is
 * exactly what a verifier must enforce rather than tolerate. Three rules
 * are therefore refusals here and not warnings:
 *
 *   The length must be definite. BER's 0x80 indefinite form, terminated
 *   by two zero bytes, lets the same structure be written two ways, and a
 *   signature is a claim about one sequence of bytes.
 *
 *   The long form must be the shortest that fits. 0x81 0x05 and 0x05 are
 *   the same length written twice, and a parser that accepts both will
 *   accept two different files as the same signature.
 *
 *   A tag number in the high-tag-number form must not be padded with
 *   leading zero septets, for the same reason.
 *
 * None of those three turns up in anything the JDK produces, so each is
 * refused rather than normalised, and the refusal is counted as a refusal.
 */
public final class Der {
	private Der() {
	}

	public static final int UNIVERSAL = 0;
	public static final int APPLICATION = 1;
	public static final int CONTEXT = 2;
	public static final int PRIVATE = 3;

	public static final int BOOLEAN = 1;
	public static final int INTEGER = 2;
	public static final int BIT_STRING = 3;
	public static final int OCTET_STRING = 4;
	public static final int NULL = 5;
	public static final int OID = 6;
	public static final int UTF8_STRING = 12;
	public static final int SEQUENCE = 16;
	public static final int SET = 17;
	public static final int PRINTABLE_STRING = 19;
	public static final int T61_STRING = 20;
	public static final int IA5_STRING = 22;
	public static final int UTC_TIME = 23;
	public static final int GENERALIZED_TIME = 24;
	public static final int BMP_STRING = 30;

	/** A malformed encoding. Checked, so no path can ignore it. */
	public static final class DerError extends Exception {
		private static final long serialVersionUID = 1L;

		public DerError(String why) {
			super(why);
		}
	}

	public static final class Node {
		public byte[] buf;
		/** Offset of the identifier octet. */
		public int off;
		/** Length of identifier plus length octets. */
		public int hl;
		/** Length of the content. */
		public int len;
		public int tagClass;
		public boolean cons;
		public int tag;
		public int depth;
		public final List<Node> kids = new ArrayList<Node>();

		public int contentOff() {
			return off + hl;
		}

		public int end() {
			return off + hl + len;
		}

		public byte[] content() {
			byte[] out = new byte[len];
			System.arraycopy(buf, contentOff(), out, 0, len);
			return out;
		}

		/** The whole encoding, identifier through content. */
		public byte[] encoded() {
			byte[] out = new byte[hl + len];
			System.arraycopy(buf, off, out, 0, out.length);
			return out;
		}

		public boolean is(int cls, int t) {
			return tagClass == cls && tag == t;
		}

		public Node kid(int i) throws DerError {
			if (i >= kids.size()) {
				throw new DerError("no child " + i + " of " + this);
			}
			return kids.get(i);
		}

		@Override
		public String toString() {
			return "[" + tagClass + " " + tag + (cons ? " cons" : " prim")
				+ " @" + off + " len " + len + "]";
		}
	}

	public static Node parse(byte[] b) throws DerError {
		return parse(b, 0, b.length);
	}

	/** Parse exactly one value, which must fill the window. */
	public static Node parse(byte[] b, int off, int len) throws DerError {
		List<Node> out = parseAll(b, off, len, 0);
		if (out.size() != 1) {
			throw new DerError(out.size() + " values where one was expected");
		}
		return out.get(0);
	}

	private static List<Node> parseAll(byte[] b, int off, int len, int depth)
			throws DerError {
		if (depth > 64) {
			throw new DerError("nested more than 64 deep");
		}
		List<Node> out = new ArrayList<Node>();
		int p = off;
		int end = off + len;
		while (p < end) {
			Node n = one(b, p, end, depth);
			out.add(n);
			p = n.end();
		}
		if (p != end) {
			throw new DerError("a value at " + off + " overruns its parent");
		}
		return out;
	}

	private static Node one(byte[] b, int p, int end, int depth)
			throws DerError {
		Node n = new Node();
		n.buf = b;
		n.off = p;
		n.depth = depth;
		if (p >= end) {
			throw new DerError("identifier octet past the end at " + p);
		}
		int id = b[p] & 0xff;
		n.tagClass = (id >> 6) & 3;
		n.cons = (id & 0x20) != 0;
		int q = p + 1;
		if ((id & 0x1f) == 0x1f) {
			int tag = 0;
			int first = -1;
			while (true) {
				if (q >= end) {
					throw new DerError("tag number runs off the end at " + p);
				}
				int c = b[q++] & 0xff;
				if (first < 0) {
					first = c;
					if ((c & 0x7f) == 0) {
						throw new DerError("tag number padded with a zero"
							+ " septet at " + p);
					}
				}
				if (tag > (Integer.MAX_VALUE >> 7)) {
					throw new DerError("tag number too large at " + p);
				}
				tag = (tag << 7) | (c & 0x7f);
				if ((c & 0x80) == 0) {
					break;
				}
			}
			if (tag < 31) {
				throw new DerError("tag " + tag + " written in the high form"
					+ " at " + p);
			}
			n.tag = tag;
		} else {
			n.tag = id & 0x1f;
		}
		if (q >= end) {
			throw new DerError("length octet past the end at " + p);
		}
		int l0 = b[q++] & 0xff;
		int length;
		if (l0 == 0x80) {
			throw new DerError("indefinite length at " + p + ", which is BER"
				+ " and not DER");
		} else if ((l0 & 0x80) == 0) {
			length = l0;
		} else {
			int nb = l0 & 0x7f;
			if (nb == 0x7f) {
				throw new DerError("reserved length form at " + p);
			}
			if (nb > 4) {
				throw new DerError("length of " + nb + " octets at " + p
					+ " is beyond this reader");
			}
			if (q + nb > end) {
				throw new DerError("length octets run off the end at " + p);
			}
			if ((b[q] & 0xff) == 0) {
				throw new DerError("length at " + p + " has a leading zero"
					+ " octet, which is not the shortest form");
			}
			length = 0;
			for (int i = 0; i < nb; i++) {
				length = (length << 8) | (b[q++] & 0xff);
			}
			if (length < 0) {
				throw new DerError("length at " + p + " does not fit in an int");
			}
			if (length < 128) {
				throw new DerError("length " + length + " at " + p + " written"
					+ " in the long form");
			}
		}
		n.hl = q - p;
		n.len = length;
		if (length > end - q) {
			throw new DerError("value at " + p + " declares " + length
				+ " bytes with " + (end - q) + " left");
		}
		if (n.cons) {
			n.kids.addAll(parseAll(b, q, length, depth + 1));
		} else if (n.tagClass == UNIVERSAL && n.tag == OID) {
			// An OBJECT IDENTIFIER whose arcs are padded encodes the same
			// name two ways. Checked here rather than at the point of use,
			// because a caller that only compares the dotted string never
			// sees the second spelling.
			if (oid(n) == null) {
				throw new DerError("malformed object identifier at " + p);
			}
		}
		return n;
	}

	/** An OBJECT IDENTIFIER in dotted form, or null if it is malformed. */
	public static String oid(Node n) {
		if (!n.is(UNIVERSAL, OID) || n.cons || n.len == 0) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		byte[] b = n.buf;
		int p = n.contentOff();
		int end = n.end();
		long v = 0;
		boolean first = true;
		int startOfArc = p;
		while (p < end) {
			int c = b[p] & 0xff;
			if (p == startOfArc && c == 0x80) {
				// A leading 0x80 pads the arc with a zero septet.
				return null;
			}
			if (v > (Long.MAX_VALUE >> 7)) {
				return null;
			}
			v = (v << 7) | (c & 0x7f);
			p++;
			if ((c & 0x80) == 0) {
				if (first) {
					long a = v / 40;
					long bb = v % 40;
					if (a > 2) {
						a = 2;
						bb = v - 80;
					}
					sb.append(a).append('.').append(bb);
					first = false;
				} else {
					sb.append('.').append(v);
				}
				v = 0;
				startOfArc = p;
			}
		}
		if (v != 0 || first) {
			return null;
		}
		return sb.toString();
	}

	/** Walk every node in document order. */
	public static void walk(Node n, List<Node> out) {
		out.add(n);
		for (Node k : n.kids) {
			walk(k, out);
		}
	}
}
