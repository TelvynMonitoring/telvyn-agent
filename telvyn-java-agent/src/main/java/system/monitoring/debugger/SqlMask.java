package system.monitoring.debugger;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Keeps the statement structure and hides every literal before a finding leaves the application.
 * Same rules as the Node agent and the backend; idempotent, so already masked text is unchanged.
 */
final class SqlMask {
    private SqlMask() {}
    // String, quoted-identifier, comment, dollar-quoted and numeric literals; an unterminated literal masks to the end.
    private static final Pattern LITERAL = Pattern.compile(
        "'(?:[^']|'')*(?:'|$)|\"(?:[^\"]|\"\")*(?:\"|$)|/\\*[\\s\\S]*?(?:\\*/|$)|--[^\\n]*|\\$([A-Za-z_]*)\\$[\\s\\S]*?(?:\\$\\1\\$|$)|(?<![\\w$])(?:0x[0-9a-f]+|\\d+(?:\\.\\d+)?(?:e[+-]?\\d+)?)(?!\\w)",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern DOLLAR_QUOTE = Pattern.compile("^\\$[A-Za-z_]*\\$");
    private static final Pattern CONTROL = Pattern.compile("[\\u0000-\\u001f\\u007f]");

    static String mask(String sql) {
        String bounded = sql.length() > 4096 ? sql.substring(0, 4096) : sql;
        Matcher matcher = LITERAL.matcher(bounded);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String match = matcher.group();
            String replacement = match.startsWith("'") ? "'<redacted>'"
                : match.startsWith("\"") ? "\"<redacted>\""
                : match.startsWith("/*") || match.startsWith("--") ? "/* <redacted> */"
                : DOLLAR_QUOTE.matcher(match).find() ? "$$<redacted>$$"
                : "<redacted>";
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        String masked = CONTROL.matcher(out).replaceAll(" ");
        return masked.length() > 2000 ? masked.substring(0, 2000) : masked;
    }
}
