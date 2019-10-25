package trust.nccgroup.decoderimproved;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
//import org.graalvm.polyglot.*;

public class JsPrettifier extends ByteModifier{
    //https://stackoverflow.com/a/48857894


    private static final String BEAUTIFY_JS_RESOURCE = "beautify.js";
    private static final String BEAUTIFY_METHOD_NAME = "js_beautify";

    private final ScriptEngine engine;
    public JsPrettifier() {

        super("JS(ON)");
        engine = new ScriptEngineManager().getEngineByName("nashorn");
        try {
            engine.eval("var global = this;");
            engine.eval(new InputStreamReader(getClass().getClassLoader().getResourceAsStream(BEAUTIFY_JS_RESOURCE)));
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }

    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        try {
            String pretty =  (String) ((Invocable) engine).invokeFunction(BEAUTIFY_METHOD_NAME, new String(input, StandardCharsets.UTF_8));
            return pretty.getBytes(StandardCharsets.UTF_8);
        } catch (ScriptException | NoSuchMethodException e) {
            throw new ModificationException("Failed to prettify JS");
        }
    }
}
