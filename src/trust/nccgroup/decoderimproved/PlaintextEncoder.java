package trust.nccgroup.decoderimproved;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextEncoder extends ByteModifier {
    public PlaintextEncoder() {
        super("Plain");
    }
    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}
