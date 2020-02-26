package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;

/**
 * Created by j on 12/7/16.
 */
public class CONSTANTS {
    public static final int COMBO_BOX_WIDTH = 180;
    public static final int COMBO_BOX_SHORT_WIDTH = 70;
    public static final int COMBO_BOX_HEIGHT = 25;
    public static final int INPUT_BOX_HEIGHT = 30;
    public static final int SEGMENT_HEIGHT = 215;
    public static final int PANEL_HEIGHT = 200;

    public static Dimension COMBO_BOX_DIMENSION = new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT);

    public static Font SMALLER_FONT = new JLabel().getFont().deriveFont((float) new JLabel().getFont().getSize() * 3 / 4);
    public static Font SMALLEST_FONT = new JLabel().getFont().deriveFont((float) new JLabel().getFont().getSize() * 1 / 4);

    public static final int META_MASK = java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();
}
