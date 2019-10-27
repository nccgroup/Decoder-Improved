package trust.nccgroup.decoderimproved;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by j on 1/6/17.
 */

public class HTMLSpecialCharEncoder extends ByteModifier {
    private String HTML_ENCODED_FORMAT_STRING = "&#%d;";
    private char[] SPECIAL_CHARS = {'"', '\'', '&', '<', '>'};

    public HTMLSpecialCharEncoder() {
        super("HTML Special Characters");
    }

    private boolean isSpecialChar(byte b) {
        for (char c : SPECIAL_CHARS) {
            if (b == c) {
                return true;
            }
        }
        return false;
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) {
        List<Byte> output = new ArrayList<>(input.length);
        for (byte b : input) {
            if (isSpecialChar(b)) {
                for (byte _b : String.format(HTML_ENCODED_FORMAT_STRING, (int) b).getBytes(StandardCharsets.UTF_8)) {
                    output.add(_b);
                }
            } else {
                output.add(b);
            }
        }
        return Utils.convertByteArrayListToByteArray(output);
    }
}

