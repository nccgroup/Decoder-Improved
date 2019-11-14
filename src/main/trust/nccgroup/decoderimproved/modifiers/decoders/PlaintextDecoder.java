package trust.nccgroup.decoderimproved.modifiers.decoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextDecoder implements ByteModifier {
    @Override
    public String getModifierName() {
        return "Plain";
    }

    @Override
    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}

