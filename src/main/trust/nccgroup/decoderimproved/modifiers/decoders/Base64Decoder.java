package trust.nccgroup.decoderimproved.modifiers.decoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.ModificationException;
import trust.nccgroup.decoderimproved.Utils;

import java.util.Base64;

/**
 * Created by j on 12/7/16.
 */

public class Base64Decoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "Base64";
    }

    // Base64 Encode the bytes
    @Override
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        // Convert from Url safe
        input = Utils.convertUrlBase64ToStandard(Utils.removeLeadingAndTrailingWhitespace(input));
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            return decoder.decode(input);
        } catch (Exception e) {
            throw new ModificationException("Invalid Base64 Input");
        }
    }
}
