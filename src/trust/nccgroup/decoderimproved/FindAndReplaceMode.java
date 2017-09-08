package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Created by j on 12/7/16.
 */

public class FindAndReplaceMode extends ModificationMode {
    // ArrayList containing all the different encoders

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
        replaceComboBox.setMaximumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        replaceComboBox.setMinimumSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));
        replaceComboBox.setPreferredSize(new Dimension(CONSTANTS.COMBO_BOX_WIDTH, CONSTANTS.COMBO_BOX_HEIGHT));

        regexBoxPanel = new JPanel();
        regexBoxPanel.setLayout(new BoxLayout(regexBoxPanel, BoxLayout.LINE_AXIS));
        regexBoxPanel.setMaximumSize(new Dimension(180, 25));
        regexBoxPanel.setMinimumSize(new Dimension(180, 25));
        regexBoxPanel.setPreferredSize(new Dimension(180, 25));

        regexLabel = new JLabel("Regex: ");
        regexTextField = new JTextField();

        replaceLabel = new JLabel("Replace: ");
        replaceTextField = new JTextField();

        regexBoxPanel.add(regexLabel);
        regexBoxPanel.add(regexTextField);

        replaceBoxPanel = new JPanel();
        replaceBoxPanel.setLayout(new BoxLayout(replaceBoxPanel, BoxLayout.LINE_AXIS));
        replaceBoxPanel.setMaximumSize(new Dimension(180, 25));
        replaceBoxPanel.setMinimumSize(new Dimension(180, 25));
        replaceBoxPanel.setPreferredSize(new Dimension(180, 25));

        replaceBoxPanel.add(replaceLabel);
        replaceBoxPanel.add(replaceTextField);

        comboBoxPanel = new JPanel();
        comboBoxPanel.setLayout(new BoxLayout(comboBoxPanel, BoxLayout.PAGE_AXIS));
        comboBoxPanel.setMaximumSize(new Dimension(180, 20));
        comboBoxPanel.setMinimumSize(new Dimension(180, 20));
        comboBoxPanel.setPreferredSize(new Dimension(180, 20));
        comboBoxPanel.add(replaceComboBox);
        comboBoxPanel.add(regexBoxPanel);
        comboBoxPanel.add(replaceBoxPanel);

        ui.add(comboBoxPanel);
    }

    // There's a limitation here. Invalid UTF-8 bytes will be replaced by the replacement char in the result.
    public byte[] modifyBytes(byte[] input) throws ModificationException{
        // Do this first to make sure the regex is valid
        try {
            Pattern.compile(regexTextField.getText());
        } catch (PatternSyntaxException e) {
            throw new ModificationException(regexTextField.getText()+" Is Not A Valid Regular Expression.");
        }
        // Do this to make sure the input is a valid string
        // Find and replace doesn't work correctly on strings containing binary data
        try {
            CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder();
            decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
            decoder.onMalformedInput(CodingErrorAction.REPORT);
            decoder.decode(ByteBuffer.wrap(input));
        } catch (Exception e) {
            throw new ModificationException("Invalid input. Find and Replace does not accept strings that contain non-UTF-8 characters.");
        }
        if ((replaceComboBox.getSelectedItem()).equals("Replace First")) {
            try {
                //String inputString = new String(input, "UTF-8");
                String inputString = UTF8StringEncoder.newUTF8String(input);
                inputString = inputString.replaceFirst(regexTextField.getText(), replaceTextField.getText());
                return inputString.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                // This should never happen
                throw new ModificationException("Invalid Input");
            }
        } else if ((replaceComboBox.getSelectedItem()).equals("Replace All")) {
            try {
                //String inputString = new String(input, "UTF-8");
                String inputString = UTF8StringEncoder.newUTF8String(input);
                inputString = inputString.replaceAll(regexTextField.getText(), replaceTextField.getText());
                return inputString.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                // This should never happen
                throw new ModificationException("Invalid input");
            }
        }
        return new byte[0];
    }
}
