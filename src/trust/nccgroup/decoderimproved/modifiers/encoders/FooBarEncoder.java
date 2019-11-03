package trust.nccgroup.decoderimproved.modifiers.encoders;

import trust.nccgroup.decoderimproved.modifiers.ByteModifier;
import trust.nccgroup.decoderimproved.ModificationException;

public class FooBarEncoder implements ByteModifier {
    public String getName() {
        return "FooBar";
    }

    // If the input = 'foo', return 'bar', otherwise throw a ModificationException
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        // All input strings are UTF-8
        if (new String(input).equals("foo")) {
            return "bar".getBytes();
        } else {
            throw new ModificationException("Invalid Input, Input is not foo");
        }
    }
}

