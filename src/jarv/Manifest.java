package jarv;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * META-INF/MANIFEST.MF and the .SF files, which share one grammar.
 *
 * Three things make this worth writing by hand rather than reaching for
 * java.util.jar.Manifest.
 *
 * The signature digests cover BYTE RANGES of this file, not parsed values,
 * so a parser that returns a map has thrown away the thing that has to be
 * right. Every section here keeps its start offset and two end offsets, one
 * excluding the blank line that follows it and one including it.
 *
 * The line length limit is 72 BYTES, not characters. A value is folded by
 * inserting a line break and a space at a byte position, which can land in
 * the middle of a UTF-8 sequence, and the JDK's own writer does exactly
 * that. So continuation lines are joined as bytes and decoded afterwards.
 * Decoding each physical line and concatenating strings corrupts any value
 * folded mid-character, and does it silently.
 *
 * A line ends with CR LF, LF, or CR alone. All three are legal and the
 * third is the one readers forget.
 */
public final class Manifest {
	public final byte[] raw;
	public final Section main;
	public final List<Section> sections = new ArrayList<Section>();
	public final List<String> problems = new ArrayList<String>();

	/** One section: the main attributes, or one entry. */
	public static final class Section {
		public int off;
		/** End offset not counting the blank line that terminates it. */
		public int endNoBlank;
		/** End offset counting the blank line. */
		public int endWithBlank;
		public final List<String> keys = new ArrayList<String>();
		public final List<String> values = new ArrayList<String>();
		/** Raw value bytes, before UTF-8 decoding. */
		public final List<byte[]> valueBytes = new ArrayList<byte[]>();
		/** The Name attribute, or null for the main section. */
		public String name;

		public String get(String key) {
			for (int i = 0; i < keys.size(); i++) {
				if (keys.get(i).equalsIgnoreCase(key)) {
					return values.get(i);
				}
			}
			return null;
		}

		/** Every value for a key, because duplicates are an attack. */
		public List<String> getAll(String key) {
			List<String> out = new ArrayList<String>();
			for (int i = 0; i < keys.size(); i++) {
				if (keys.get(i).equalsIgnoreCase(key)) {
					out.add(values.get(i));
				}
			}
			return out;
		}

		/**
		 * A key ending in "-Digest", with its algorithm name. The JAR spec
		 * allows any digest algorithm and names it in the attribute, so
		 * the set of digests in a section is discovered, not assumed.
		 */
		public List<String> digestAlgorithms() {
			List<String> out = new ArrayList<String>();
			for (String k : keys) {
				if (k.length() > 7 && k.regionMatches(true, k.length() - 7, "-Digest", 0, 7)) {
					out.add(k.substring(0, k.length() - 7));
				}
			}
			return out;
		}
	}

	public Manifest(byte[] raw) {
		this.raw = raw;
		int i = 0;
		Section first = null;
		while (i < raw.length) {
			Section s = new Section();
			i = readSection(s, i);
			if (s.keys.isEmpty() && s.off == s.endWithBlank) {
				break;
			}
			if (first == null) {
				first = s;
			} else {
				if (s.keys.isEmpty()) {
					// A run of blank lines between sections. Not an error
					// in any producer seen here, and not a section either.
					continue;
				}
				if (!"Name".equalsIgnoreCase(s.keys.get(0))) {
					problems.add("section at " + s.off + " starts with "
						+ s.keys.get(0) + ", not Name");
				}
				s.name = s.get("Name");
				if (s.name == null) {
					problems.add("section at " + s.off + " has no Name");
				}
				sections.add(s);
			}
		}
		main = first == null ? new Section() : first;
		for (int a = 0; a < sections.size(); a++) {
			for (int b = a + 1; b < sections.size(); b++) {
				String na = sections.get(a).name;
				if (na != null && na.equals(sections.get(b).name)) {
					problems.add("two sections both name " + na
						+ ", at " + sections.get(a).off + " and "
						+ sections.get(b).off);
				}
			}
		}
	}

	/**
	 * Read one section starting at off. Returns the offset of the next.
	 *
	 * The two end offsets are what the signature file digests are taken
	 * over, so they are recorded here even though nothing in this class
	 * uses them.
	 */
	private int readSection(Section s, int off) {
		s.off = off;
		int i = off;
		List<byte[]> lines = new ArrayList<byte[]>();
		List<Integer> starts = new ArrayList<Integer>();
		int lastLineEnd = off;
		while (i < raw.length) {
			int lineStart = i;
			int contentEnd = i;
			while (contentEnd < raw.length && raw[contentEnd] != '\n'
					&& raw[contentEnd] != '\r') {
				contentEnd++;
			}
			int next = contentEnd;
			if (next < raw.length) {
				if (raw[next] == '\r' && next + 1 < raw.length
						&& raw[next + 1] == '\n') {
					next += 2;
				} else {
					next += 1;
				}
			}
			if (contentEnd == lineStart) {
				// Blank line: the section ends before it, the next section
				// starts after it.
				s.endNoBlank = lineStart;
				s.endWithBlank = next;
				parse(s, lines, starts);
				return next;
			}
			byte[] line = new byte[contentEnd - lineStart];
			System.arraycopy(raw, lineStart, line, 0, line.length);
			lines.add(line);
			starts.add(Integer.valueOf(lineStart));
			lastLineEnd = next;
			i = next;
		}
		// Ran off the end with no blank line after the last section. The
		// two end offsets coincide; jarsigner's writer always leaves the
		// blank line, so this is the hand-edited case.
		s.endNoBlank = lastLineEnd;
		s.endWithBlank = lastLineEnd;
		parse(s, lines, starts);
		return i;
	}

	private void parse(Section s, List<byte[]> lines, List<Integer> starts) {
		List<byte[]> logical = new ArrayList<byte[]>();
		List<Integer> logicalAt = new ArrayList<Integer>();
		for (int n = 0; n < lines.size(); n++) {
			byte[] l = lines.get(n);
			if (l.length > 0 && l[0] == ' ') {
				if (logical.isEmpty()) {
					problems.add("continuation line at " + starts.get(n)
						+ " with nothing to continue");
					continue;
				}
				// Exactly one leading space is the marker. Everything after
				// it, spaces included, is value. Stripping all leading
				// whitespace loses a value that genuinely begins with one.
				byte[] prev = logical.get(logical.size() - 1);
				byte[] joined = new byte[prev.length + l.length - 1];
				System.arraycopy(prev, 0, joined, 0, prev.length);
				int k = 0; while (k < l.length && l[k] == 32) { k++; } byte[] j2 = new byte[prev.length + l.length - k]; System.arraycopy(prev, 0, j2, 0, prev.length); System.arraycopy(l, k, j2, prev.length, l.length - k); joined = j2;
				logical.set(logical.size() - 1, joined);
			} else {
				logical.add(l);
				logicalAt.add(starts.get(n));
			}
		}
		for (int n = 0; n < logical.size(); n++) {
			byte[] l = logical.get(n);
			int colon = -1;
			for (int j = 0; j < l.length; j++) {
				if (l[j] == ':') {
					colon = j;
					break;
				}
			}
			if (colon < 0 || colon + 1 >= l.length || l[colon + 1] != ' ') {
				problems.add("line at " + logicalAt.get(n)
					+ " is not name followed by colon space");
				continue;
			}
			byte[] key = new byte[colon];
			System.arraycopy(l, 0, key, 0, colon);
			byte[] val = new byte[l.length - colon - 2];
			System.arraycopy(l, colon + 2, val, 0, val.length);
			s.keys.add(new String(key, StandardCharsets.UTF_8));
			s.valueBytes.add(val);
			s.values.add(new String(val, StandardCharsets.UTF_8));
		}
	}

	/** The section for an entry name, or null. */
	public Section forName(String name) {
		for (Section s : sections) {
			if (name.equals(s.name)) {
				return s;
			}
		}
		return null;
	}
}
