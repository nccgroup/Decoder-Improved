package trust.nccgroup.decoderimproved;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextDecoder extends ByteModifier {
    public PlaintextDecoder() {
        super("Plain");
    }
    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}

