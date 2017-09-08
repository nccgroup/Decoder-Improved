package trust.nccgroup.decoderimproved;

public class FooBarEncoder extends ByteModifier {
    public FooBarEncoder() {
        super("FooBar");
    }

    // If the input = 'foo', return 'bar', otherwise throw a ModificationException
    public byte[] modifyBytes(byte[] input) throws  ModificationException{
        // All input strings are UTF-8
        if (new String(input).equals("foo")) {
            return "bar".getBytes();
        } else {
            throw new ModificationException("Invalid Input, Input is not foo");
        }
    }
}

