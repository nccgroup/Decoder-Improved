package trust.nccgroup.decoderimproved.modifiers.decoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.ModificationException;

import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;

/**
 * Created by j on 4/7/17.
 */
public class ASCIIHexDecoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "ASCII Hex";
    }

    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        String inputString;
        inputString = new String(input, StandardCharsets.UTF_8);
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
