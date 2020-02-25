package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.CONSTANTS;
import trust.nccgroup.decoderimproved.modifiers.ByteModifier;

import javax.swing.*;
import java.awt.*;

/**
 * Created by j on 12/6/16.
 */
public abstract class AbstractModificationMode implements ByteModifier {
    protected JPanel ui;
    private String name;
    private CardLayout layoutManager;

    public abstract JsonObject toJSON();
    public abstract void setFromJSON(JsonObject jsonObject);

    public AbstractModificationMode(String name) {
        this.name = name;
        layoutManager = new CardLayout();
        ui = new JPanel(layoutManager);

        // Set the JPanel default sizes
        ui.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        ui.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        ui.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);
    }

    public JPanel getUI() {
        return ui;
    }

    public String getModeName() {
        return name;
    }
}
