package trust.nccgroup.decoderimproved.modifiers;

import trust.nccgroup.decoderimproved.ModificationException;

/**
 * Created by j on 12/6/16.
 */
public abstract class AbstractByteModifier {
    private String name;

    public abstract byte[] modifyBytes(byte[] input) throws ModificationException;

    public AbstractByteModifier(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }
}
