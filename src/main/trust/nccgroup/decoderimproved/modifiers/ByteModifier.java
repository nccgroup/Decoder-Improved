package trust.nccgroup.decoderimproved.modifiers;

import trust.nccgroup.decoderimproved.ModificationException;

/**
 * Created by j on 12/6/16.
 */
public interface ByteModifier {
    byte[] modifyBytes(byte[] input) throws ModificationException;
    String getModifierName();
}
