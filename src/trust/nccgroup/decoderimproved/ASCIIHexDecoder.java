package trust.nccgroup.decoderimproved;

import java.io.UnsupportedEncodingException;
import javax.xml.bind.DatatypeConverter;

/**
 * Created by j on 4/7/17.
 */
public class ASCIIHexDecoder extends ByteModifier{
    public ASCIIHexDecoder() {
        super("ASCII Hex");
    }

    // URL Encode the bytes
    public byte[] modifyBytes(byte[] input) throws ModificationException{
        String inputString;
        try {
            inputString = new String(input, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new ModificationException("Invalid Hex String");
        }
        try {
            return DatatypeConverter.parseHexBinary(inputString);
        } catch (IllegalArgumentException e) {
            throw new ModificationException("Invalid Hex String");
        }

        //String output = "";
        //for (byte b : input) {
        //    output += String.format("%02X", (0xFF & (int)b));
        //}
        //try {
        //    return output.getBytes("UTF-8");
        //} catch (UnsupportedEncodingException e) {
        //    return new byte[0];
        //}
    }

}
