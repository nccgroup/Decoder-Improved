package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;

/**
 * Created by j on 1/6/17.
 */

public class HTMLEncoder extends ByteModifier {
    String HTML_ENCODED_FORMAT_STRING = "&#%d;";
    public HTMLEncoder() {
        super("HTML");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) throws ModificationException{
        StringBuilder output = new StringBuilder();
        try {
            CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder();
            decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
            decoder.onMalformedInput(CodingErrorAction.REPORT);
            decoder.decode(ByteBuffer.wrap(input));

            // String displayString = new String(input, "UTF-8");
            String displayString = UTF8StringEncoder.newUTF8String(input);

            for (int i = 0; i < displayString.length(); i++) {
                int charCodePoint = Character.codePointAt(displayString, i);
                output.append(String.format(HTML_ENCODED_FORMAT_STRING, charCodePoint));
            }

        } catch (Exception e) {
            throw new ModificationException("Invalid input. HTML encoding does not accept strings that contain non-UTF-8 characters.");
        }
        try {
            return output.toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new ModificationException("Invalid output");
        }
    }
}
