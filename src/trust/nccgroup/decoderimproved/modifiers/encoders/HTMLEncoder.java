package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.UTF8StringEncoder;
import trust.nccgroup.decoderimproved.Utils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by j on 1/6/17.
 */

public class HTMLEncoder implements ByteModifier {
    private String HTML_ENCODED_FORMAT_STRING = "&#%d;";

    public String getName() {
        return "HTML";
    }

    public byte[] modifyBytes(byte[] input) {
        List<Byte> output = new ArrayList<>(input.length);
        for (int i = 0; i < input.length; i++) {
            byte b = input[i];
            boolean isMultibyte = false;
            int codepoint = -1;
            int expectedLength = Utils.multibyteExpectLength(b);
            if (expectedLength > 1 && i + expectedLength - 1 < input.length) {
                byte[] multibyte = Arrays.copyOfRange(input, i, i + expectedLength);
                if (Utils.isUTF8Char(multibyte)) {
                    String multibyteString = UTF8StringEncoder.newUTF8String(multibyte);
                    if (multibyteString.length() == 1) {
                        codepoint = multibyteString.codePointAt(0);
                        i += expectedLength - 1;
                        isMultibyte = true;
                    }
                }
            }
            if (!isMultibyte) {
                codepoint = b & 0xff;
            }
            for (byte _b : String.format(HTML_ENCODED_FORMAT_STRING, codepoint).getBytes(StandardCharsets.UTF_8)) {
                output.add(_b);
            }
        }
        return Utils.convertByteArrayListToByteArray(output);
    }
}
