package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextEncoder implements ByteModifier {
    public final static String NAME = "Plain";

    public String getName() {
        return NAME;
    }

    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}
