package trust.nccgroup.decoderimproved;

/**
 * Created by j on 12/6/16.
 */
public class PlaintextEncoder extends ByteModifier {
    public static String NAME = "Plain";

    public PlaintextEncoder() {
        super(NAME);
    }
    public byte[] modifyBytes(byte[] input) {
        return input;
    }
}
