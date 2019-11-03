package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.CONSTANTS;
import trust.nccgroup.decoderimproved.Logger;

import javax.swing.*;

/**
 * Created by j on 12/7/16.
 */

public class TextReplaceMode extends AbstractModificationMode {
    // Swing components
    private JLabel replaceLabel;
    private JTextField replaceTextField;
    private JPanel replaceBoxPanel;
    private JPanel comboBoxPanel;

    public TextReplaceMode() {
        // The name to appear in the combo box
        super("Replace");

        // The replacement text field and label
        replaceLabel = new JLabel("Replace: ");
        replaceTextField = new JTextField();

        // Need to make a JPanel to contain the textfield and label
        replaceBoxPanel = new JPanel();
        replaceBoxPanel.setLayout(new BoxLayout(replaceBoxPanel, BoxLayout.LINE_AXIS));
        replaceBoxPanel.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        replaceBoxPanel.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        replaceBoxPanel.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);

        // Add the label and the text field
        replaceBoxPanel.add(replaceLabel);
        replaceBoxPanel.add(replaceTextField);

        // Need a second JPanel to contain the first to keep the sizing correct.
        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.add(replaceBoxPanel);

        // UI is a JPanel defined within ModificationMode that is used to draw the UI
        ui.add(comboBoxPanel);
    }

    public byte[] modifyBytes(byte[] input) {
        return replaceTextField.getText().getBytes();
    }

    public JsonObject toJSON() {
        Logger.printError("TextReplaceMode not in use. Not implemented!");
        return null;
    }

    public void setFromJSON(JsonObject jsonObject) {
        Logger.printError("TextReplaceMode not in use. Not implemented!");
    }
}
