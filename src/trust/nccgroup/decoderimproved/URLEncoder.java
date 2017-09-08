package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;

/**
 * Created by j on 12/6/16.
 */
public class URLEncoder extends ByteModifier {
    public URLEncoder() {
        super("URL");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) throws ModificationException{
        String output = "";

        for (byte b : input) {
            output += "%";
            output += String.format("%02X", (0xFF & (int)b));
        }
        try {
            return output.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
			// This should never happen
            throw new ModificationException("Invalid Input");
        }
    }
}
