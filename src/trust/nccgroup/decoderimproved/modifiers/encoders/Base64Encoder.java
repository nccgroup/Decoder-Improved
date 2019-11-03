package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

import java.util.Base64;

/**
 * Created by j on 12/6/16.
 */
public class Base64Encoder implements ByteModifier {
    public String getName() {
        return "Base64";
    }

    public byte[] modifyBytes(byte[] input) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encode(input);
    }
}

