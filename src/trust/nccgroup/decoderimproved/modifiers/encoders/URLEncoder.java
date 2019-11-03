package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

import java.nio.charset.StandardCharsets;

/**
 * Created by j on 12/6/16.
 */
public class URLEncoder implements ByteModifier {
    public String getName() {
        return "URL";
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) {
        StringBuilder output = new StringBuilder();

        for (byte b : input) {
            output.append("%");
            output.append(String.format("%02X", (0xFF & (int) b)));
        }
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }
}
