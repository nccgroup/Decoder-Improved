package trust.nccgroup.decoderimproved;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

class ConfigPanel extends JPanel {
    private JButton exportButton;
    private JButton loadButton;
    private JToggleButton clearButton;

    public ConfigPanel(ExtensionRoot extensionRoot) {
        this.setLayout(new FlowLayout(FlowLayout.LEFT));
        exportButton = new JButton("Export all tabs to file");
        loadButton = new JButton("Load tabs from file");
        String clearButtonText = "Clear all tabs on exit";
        clearButton = new JToggleButton(clearButtonText);

        this.add(exportButton);
        this.add(loadButton);
        this.add(clearButton);

        // Listeners
        exportButton.addActionListener((e) -> {
            try {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save all data to...");
                // Grab focus to save file dialog
                fileChooser.addHierarchyListener((_event) -> {
                    grabFocus();
                });
                if (fileChooser.showSaveDialog(extensionRoot.multiDecoderTab) == JFileChooser.APPROVE_OPTION) {
                    FileOutputStream fileOutputStream = new FileOutputStream(fileChooser.getSelectedFile());
                    // Get state and write to file
                    fileOutputStream.write(extensionRoot.multiDecoderTab.getState().getBytes());
                    fileOutputStream.close();
                }
            } catch (Exception ee) {
                Logger.printErrorFromException(ee);
            }
        });

        loadButton.addActionListener((e) -> {
            try {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Load data from...");
                // Grab focus to load file dialog
                fileChooser.addHierarchyListener((_event) -> {
                    grabFocus();
                });
                if (fileChooser.showOpenDialog(extensionRoot.multiDecoderTab) == JFileChooser.APPROVE_OPTION) {
                    // Read file content
                    File selectedFile = fileChooser.getSelectedFile();
                    FileInputStream fileInputStream = new FileInputStream(selectedFile);
                    byte[] fileContent = new byte[(int) selectedFile.length()];
                    fileInputStream.read(fileContent);
                    fileInputStream.close();
                    extensionRoot.multiDecoderTab.setState(new String(fileContent), false);
                }
            } catch (Exception ee) {
                Logger.printErrorFromException(ee);
                JOptionPane.showMessageDialog(extensionRoot.multiDecoderTab, ee.getClass().getName() + ", please check extension errors for details", "Error loading file", JOptionPane.ERROR_MESSAGE);
            }
        });

        clearButton.addItemListener((e) -> {
            try {
                if (clearButton.isSelected()) {
                    extensionRoot.setClearState();
                    clearButton.setText("ALL TABS will be CLEARED on exit");
                } else {
                    extensionRoot.setSaveFullState();
                    clearButton.setText(clearButtonText);
                }
            } catch (Exception ee) {
                Logger.printErrorFromException(ee);
            }
        });
    }
}
