package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;

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
        try {
            return output.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            return new byte[0];
        }
    }
}

