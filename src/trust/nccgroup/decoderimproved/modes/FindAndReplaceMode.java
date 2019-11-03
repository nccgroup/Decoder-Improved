package trust.nccgroup.decoderimproved.modes;

import com.google.gson.JsonObject;
import trust.nccgroup.decoderimproved.*;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Created by j on 12/7/16.
 */

public class FindAndReplaceMode extends AbstractModificationMode {
    // Swing components
    private String[] REPLACE_LABELS;
    private JComboBox<String> replaceComboBox;
    private JPanel regexBoxPanel;
    private JTextField regexTextField;
    private JLabel regexLabel;
    private JLabel replaceLabel;
    private JTextField replaceTextField;
    private JPanel replaceBoxPanel;
    private JPanel comboBoxPanel;

    public FindAndReplaceMode() {
        super("Find and Replace");

        REPLACE_LABELS = new String[]{"Replace First", "Replace All"};
        replaceComboBox = new JComboBox<>(REPLACE_LABELS);
        replaceComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        replaceComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        replaceComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));

        regexBoxPanel = new JPanel();
        regexBoxPanel.setLayout(new BoxLayout(regexBoxPanel, BoxLayout.LINE_AXIS));
        regexBoxPanel.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        regexBoxPanel.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        regexBoxPanel.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));


        regexLabel = new JLabel("Regex: ");
        replaceLabel = new JLabel("Replace: ");

        float labelFontSize = (float)regexLabel.getFont().getSize() * 3 / 4;

        regexLabel.setFont(regexLabel.getFont().deriveFont(labelFontSize));
        regexTextField = new JTextField();
        replaceLabel.setFont(replaceLabel.getFont().deriveFont(labelFontSize));
        replaceTextField = new JTextField();

        regexBoxPanel.add(regexLabel);
        regexBoxPanel.add(regexTextField);

        replaceBoxPanel = new JPanel();
        replaceBoxPanel.setLayout(new BoxLayout(replaceBoxPanel, BoxLayout.LINE_AXIS));
        replaceBoxPanel.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        replaceBoxPanel.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        replaceBoxPanel.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));

        replaceBoxPanel.add(replaceLabel);
        replaceBoxPanel.add(replaceTextField);

        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        comboBoxPanel.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        comboBoxPanel.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.INPUT_BOX_HEIGHT));
        comboBoxPanel.add(replaceComboBox);
        comboBoxPanel.add(regexBoxPanel);
        comboBoxPanel.add(replaceBoxPanel);

        ui.add(comboBoxPanel);
    }

    // There's a limitation here. Invalid UTF-8 bytes will be replaced by the replacement char in the result.
    public byte[] modifyBytes(byte[] input) throws ModificationException {
        String regexText = regexTextField.getText();
        if (regexText == null || regexText.isEmpty()) {
            return input;
        }
        // Do this first to make sure the regex is valid
        try {
            Pattern.compile(regexText);
        } catch (PatternSyntaxException e) {
            throw new ModificationException(regexText + " Is Not A Valid Regular Expression.");
        }
        // Do this to make sure the input is a valid string
        // Find and replace doesn't work correctly on strings containing binary data
        /* fixme: I didn't notice error when replacing a string that contains non-UTF-8 chars - fix me if anything is wrong
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
            decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
            decoder.onMalformedInput(CodingErrorAction.REPORT);
            decoder.decode(ByteBuffer.wrap(input));
        } catch (Exception e) {
            throw new ModificationException("Invalid input. Find and Replace does not accept strings that contain non-UTF-8 characters.");
        }*/
        if ((replaceComboBox.getSelectedItem()).equals("Replace First")) {
            //String inputString = new String(input, "UTF-8");
            String inputString = UTF8StringEncoder.newUTF8String(input);
            inputString = inputString.replaceFirst(regexText, replaceTextField.getText());
            return inputString.getBytes(StandardCharsets.UTF_8);
        } else if ((replaceComboBox.getSelectedItem()).equals("Replace All")) {
            //String inputString = new String(input, "UTF-8");
            String inputString = UTF8StringEncoder.newUTF8String(input);
            inputString = inputString.replaceAll(regexText, replaceTextField.getText());
            return inputString.getBytes(StandardCharsets.UTF_8);
        }
        return new byte[0];
    }

    public JsonObject toJSON() {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("c", (String) replaceComboBox.getSelectedItem());
        jsonObject.addProperty("g", regexTextField.getText());
        jsonObject.addProperty("p", replaceTextField.getText());
        return jsonObject;
    }

    public void setFromJSON(JsonObject jsonObject) {
        try {
            replaceComboBox.setSelectedItem(jsonObject.get("c").getAsString());
            regexTextField.setText(jsonObject.get("g").getAsString());
            replaceTextField.setText(jsonObject.get("p").getAsString());
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }
    }
}
