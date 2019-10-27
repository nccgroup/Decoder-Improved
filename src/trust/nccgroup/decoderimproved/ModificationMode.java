package trust.nccgroup.decoderimproved;

import com.google.gson.JsonObject;

import javax.swing.*;
import java.awt.*;

/**
 * Created by j on 12/6/16.
 */
public abstract class ModificationMode {
    JPanel ui;
    String name;
    private CardLayout layoutManager;

    public abstract JsonObject toJSON();
    public abstract void setFromJSON(JsonObject jsonObject);

    ModificationMode() {
        this.name = "";
        layoutManager = new CardLayout();
        this.ui = new JPanel(layoutManager);
    }

    ModificationMode(String name) {
        this.name = name;
        layoutManager = new CardLayout();
        this.ui = new JPanel(layoutManager);

        // Set the JPanel default sizes
        ui.setMaximumSize(new Dimension(180, 20));
        ui.setMinimumSize(new Dimension(180, 20));
        ui.setPreferredSize(new Dimension(180, 20));
    }

    public JPanel getUI() {
        return ui;
    }

    public String getName() {
        return name;
    }

    public void setUI(JPanel ui) {
        this.ui = ui;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] modifyBytes(byte [] input) throws ModificationException{
        return input;
    }
}
