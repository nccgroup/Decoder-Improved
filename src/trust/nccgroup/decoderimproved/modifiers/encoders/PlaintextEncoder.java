package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextEncoder extends AbstractByteModifier {
    public final static String NAME = "Plain";

    public PlaintextEncoder() {
        super(NAME);
    }
    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}
