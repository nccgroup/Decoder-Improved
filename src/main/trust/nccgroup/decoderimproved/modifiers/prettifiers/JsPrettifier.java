package trust.nccgroup.decoderimproved.modifiers.prettifiers;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import trust.nccgroup.decoderimproved.Logger;
import trust.nccgroup.decoderimproved.ModificationException;
import trust.nccgroup.decoderimproved.Utils;
import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.stream.Collectors;

public class JsPrettifier implements ByteModifier {
    // https://parsiya.net/blog/2019-12-22-using-mozilla-rhino-to-run-javascript-in-java/

    @Override
    public String getModifierName() {
        return "JS(ON)";
    }

    private static final String BEAUTIFY_JS_RESOURCE = "beautify.js";
    private static final String BEAUTIFY_METHOD_NAME = "js_beautify";
    private static final String BEAUTIFY_JS = new BufferedReader(new InputStreamReader(
            Objects.requireNonNull(JsPrettifier.class.getClassLoader().getResourceAsStream(BEAUTIFY_JS_RESOURCE)))
    ).lines().collect(Collectors.joining(System.lineSeparator()));

    public JsPrettifier() {

    }

    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        try {
            String inputString = new String(input, StandardCharsets.UTF_8);
            // The org.mozilla.javascript.Context is per-thread,
            // which has to be initialized (Context.enter()) and removed (Context.exit()) every time.
            // Fortunately, at a glimpse of how it is implemented, it's expected that a Context is being reused rather than re-created every time.
            Context context = Context.enter();
            Scriptable scope = context.initStandardObjects();
            context.evaluateString(scope, "var global = {};", "global", 1, null);
            context.evaluateString(scope, BEAUTIFY_JS, "beautify", 1, null);
            scope.put("source", scope, inputString);
            context.evaluateString(scope, "result = global." + BEAUTIFY_METHOD_NAME + "(source);", "beautify", 1, null);
            String result = (String) scope.get("result", scope);
            Context.exit();
            return result.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new ModificationException("Failed to prettify JS");
        }
    }
}
