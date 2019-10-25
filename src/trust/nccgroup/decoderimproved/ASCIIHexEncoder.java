package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

/**
 * Created by j on 12/6/16.
 */
public class ASCIIHexEncoder extends ByteModifier {
    public ASCIIHexEncoder() {
        super("ASCII Hex");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) {
        String output = "";
        for (byte b : input) {
            output += String.format("%02X", (0xFF & (int)b));
        }
        return output.getBytes(StandardCharsets.UTF_8);
    }
}

