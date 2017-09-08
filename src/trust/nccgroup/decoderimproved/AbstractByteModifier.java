package trust.nccgroup.decoderimproved;

import javax.swing.*;

/**
 * Created by j on 12/6/16.
 */
abstract class AbstractByteModifier {
    abstract byte[] modifyBytes(byte[] input) throws ModificationException;
    abstract String getName();
    abstract JPanel getUI();
}
