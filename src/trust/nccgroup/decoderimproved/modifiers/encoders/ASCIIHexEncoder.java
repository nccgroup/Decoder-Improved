package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;

import java.nio.charset.StandardCharsets;

/**
 * Created by j on 12/6/16.
 */
public class ASCIIHexEncoder extends AbstractByteModifier {
    public ASCIIHexEncoder() {
        super("ASCII Hex");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) {
        StringBuilder output = new StringBuilder();
        for (byte b : input) {
            output.append(String.format("%02X", (0xFF & (int) b)));
        }
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }
}

