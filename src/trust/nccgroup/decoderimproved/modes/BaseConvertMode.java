package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.*;

import javax.swing.*;
import java.awt.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Created by j on 12/7/16.
 */

public class BaseConvertMode extends AbstractModificationMode {
    // Swing components
    private JComboBox<String> fromBaseComboBox;
    private JComboBox<String> toBaseComboBox;
    private JPanel comboBoxPanel;
    private String[] CHANGE_BASE_LABELS;
    private JLabel toBaseLabel;
    private JLabel fromBaseLabel;

    private JPanel toPanel;
    private JPanel fromPanel;

    public BaseConvertMode() {
        super("Numeric Base");

        CHANGE_BASE_LABELS = new String[]{"Base 2", "Base 3", "Base 4", "Base 5",
                "Base 6", "Base 7", "Base 8", "Base 9", "Base 10", "Base 11",
                "Base 12", "Base 13", "Base 14", "Base 15", "Base 16", "Base 17",
                "Base 18", "Base 19", "Base 20", "Base 21", "Base 22", "Base 23", "Base 24",
                "Base 25", "Base 26", "Base 27", "Base 28", "Base 29", "Base 30",
                "Base 31", "Base 32"};

        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
        comboBoxPanel.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);

        // Swing Components
        toBaseComboBox = new JComboBox<>(CHANGE_BASE_LABELS);
        toBaseComboBox.setMaximumSize(new Dimension(90, CONSTANTS.COMBO_BOX_HEIGHT));
        toBaseComboBox.setMinimumSize(new Dimension(90, CONSTANTS.COMBO_BOX_HEIGHT));
        toBaseComboBox.setPreferredSize(new Dimension(90, CONSTANTS.COMBO_BOX_HEIGHT));
        toBaseComboBox.setAlignmentX(Component.RIGHT_ALIGNMENT);
        toBaseComboBox.setSelectedIndex(8);

        fromBaseComboBox = new JComboBox<>(CHANGE_BASE_LABELS);
        fromBaseComboBox.setMaximumSize(new Dimension(90, CONSTANTS.COMBO_BOX_HEIGHT));
        fromBaseComboBox.setMinimumSize(new Dimension(90, CONSTANTS.COMBO_BOX_HEIGHT));
        fromBaseComboBox.setPreferredSize(new Dimension(90, CONSTANTS.COMBO_BOX_HEIGHT));
        fromBaseComboBox.setAlignmentX(Component.RIGHT_ALIGNMENT);
        fromBaseComboBox.setSelectedIndex(8);

        toPanel = new JPanel();
        toPanel.setLayout(new BoxLayout(toPanel, BoxLayout.LINE_AXIS));

        fromPanel = new JPanel();
        fromPanel.setLayout(new BoxLayout(fromPanel, BoxLayout.LINE_AXIS));

        fromBaseLabel = new JLabel("From: ");

        toBaseLabel = new JLabel("To:     ");

        fromPanel.add(fromBaseLabel);
        fromPanel.add(fromBaseComboBox);

        toPanel.add(toBaseLabel);
        toPanel.add(toBaseComboBox);

        comboBoxPanel.add(fromPanel);
        comboBoxPanel.add(toPanel);

        ui.add(comboBoxPanel);
    }

    public byte[] modifyBytes(byte[] input) throws ModificationException {
        String numericString = UTF8StringEncoder.newUTF8String(input);
        try {
            BigInteger convertedNumber = new BigInteger(numericString, fromBaseComboBox.getSelectedIndex() + 2);
            String convertedNumberString = convertedNumber.toString(toBaseComboBox.getSelectedIndex() + 2);
            return convertedNumberString.getBytes(StandardCharsets.UTF_8);
        } catch (NumberFormatException e) {
            throw new ModificationException("Invalid " + fromBaseComboBox.getSelectedItem() + " Number");
        }
    }

    public JsonObject toJSON() {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("f", (String) fromBaseComboBox.getSelectedItem());
        jsonObject.addProperty("t", (String) toBaseComboBox.getSelectedItem());
        return jsonObject;
    }

    public void setFromJSON(JsonObject jsonObject) {
        try {
            fromBaseComboBox.setSelectedItem(jsonObject.get("f").getAsString());
            toBaseComboBox.setSelectedItem(jsonObject.get("t").getAsString());
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
    }
}

