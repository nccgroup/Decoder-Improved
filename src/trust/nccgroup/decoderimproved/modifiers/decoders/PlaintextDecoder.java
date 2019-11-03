package trust.nccgroup.decoderimproved.modifiers.decoders;

import trust.nccgroup.decoderimproved.modifiers.AbstractByteModifier;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextDecoder extends AbstractByteModifier {
    public PlaintextDecoder() {
        super("Plain");
    }
    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}

