package trust.nccgroup.decoderimproved;

import burp.ITab;
import com.google.gson.*;
import trust.nccgroup.decoderimproved.modes.AbstractModificationMode;
import trust.nccgroup.decoderimproved.modifiers.encoders.PlaintextEncoder;
import trust.nccgroup.decoderimproved.modes.EncodeMode;
import util.PDControlScrollPane;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.deltahex.DataChangedListener;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.ArrayList;
import java.util.Base64;

import org.exbin.deltahex.CodeType;

class MultiDecoderTab extends JPanel implements ITab {

    private JTabbedPane main;
    private JPanel newTabButton;

    private ConfigPanel configPanel;

    private boolean tabChangeListenerLock = false;

    //Plugin starts with one decoder tab open and the "new tab" tab
    private int overallCount = 0;

    public boolean isTabChangeListenerLock() {
        return tabChangeListenerLock;
    }

    private void setTabChangeListenerLock(boolean tabChangeListenerLock) {
        this.tabChangeListenerLock = tabChangeListenerLock;
    }

    public MultiDecoderTab(ExtensionRoot extensionRoot) {
        // Set main tab layout
        setLayout(new BorderLayout());
        //initialize ui elements
        main = new JTabbedPane();

        // Add "new tab" tab
        newTabButton = new JPanel();
        newTabButton.setName("...");
        main.add(newTabButton);

        main.addChangeListener((ChangeEvent e) -> {
            // If the '...' button is pressed, add a new tab

            if(!tabChangeListenerLock) {
                if (main.getSelectedIndex() == main.getTabCount()-1) {
                    addTab();
                } else {
                    DecoderTab dt = (DecoderTab) main.getSelectedComponent();
                    dt.getDecoderSegments().get(0).getTextEditor().requestFocus();
                }
            }
            for (int i = 0; i < main.getTabCount()-2; i++) {
                DecoderTab.DecoderTabHandle dth = (DecoderTab.DecoderTabHandle) main.getTabComponentAt(i);
                dth.tabName.setEditable(false);
            }
        });
        add(main, BorderLayout.CENTER);

        configPanel = new ConfigPanel(extensionRoot);
        add(configPanel, BorderLayout.SOUTH);
    }

    // Logic for adding new tabs
    private void addTab() {
        tabChangeListenerLock = true;
        // Add a new tab
        overallCount += 1;
        DecoderTab mt2 = new DecoderTab(Integer.toString(overallCount, 10), this);
        main.add(mt2);
        main.setTabComponentAt(main.indexOfComponent(mt2), mt2.getTabHandleElement());
        main.setSelectedComponent(mt2);
        //mt2.getDecoderSegments().get(0).getTextEditor().requestFocus();

        // This moves the '...' tab to the end of the tab list
        main.remove(newTabButton);
        main.add(newTabButton);

        tabChangeListenerLock = false;
    }

    private int firstEmptyDecoder() {
        if (main.getComponentAt(main.getTabCount()-2) instanceof DecoderTab) {
            DecoderTab dt = (DecoderTab) main.getComponentAt(main.getTabCount()-2);
            if (dt.getDecoderSegments().get(0).dsState.getDisplayString().equals("")) {
                return main.getTabCount() - 2;
            }
        }
        return -1;
    }

    public void receiveTextFromMenu(byte[] selectedTextBytes) {
        // TODO: Add checks to see if the decoder segment is populated.
        if (firstEmptyDecoder() == -1) {
            // Add a new tab
            addTab();
            DecoderTab dt = (DecoderTab) main.getComponentAt(main.getTabCount()-2);
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0);
            for (DecoderSegment ds : dt.getDecoderSegments()) {
                ds.updateEditors(dt.getDecoderSegments().get(0).dsState);
            }
        } else {
            DecoderTab dt = (DecoderTab) main.getComponentAt(firstEmptyDecoder());
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0);
            for (DecoderSegment ds : dt.getDecoderSegments()) {
                ds.updateEditors(dt.getDecoderSegments().get(0).dsState);
            }
        }
    }

    @Override
    public String getTabCaption() {
        return "Decoder Improved";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    private JTabbedPane getMain() { return main; }

    // Save the current state of extension to a JsonObject string
    public String getState() {
        JsonObject extensionStateObject = new JsonObject();
        JsonArray tabStateArray = new JsonArray();
        // Save all tabs except the last "..." one
        for (int i = 0; i < main.getTabCount() - 1; i++) {
            JsonObject tabStateObject = new JsonObject();
            DecoderTab.DecoderTabHandle tabHandle = (DecoderTab.DecoderTabHandle) main.getTabComponentAt(i);
            // Tab name
            tabStateObject.addProperty("n", tabHandle.tabName.getText());
            // Bytes in first segment of each tab
            tabStateObject.addProperty("b", Base64.getEncoder().encodeToString(tabHandle.decoderTab.getDecoderSegments().get(0).dsState.getByteArray()));
            // Save panel states of all segments
            JsonArray segmentStateArray = new JsonArray();
            for (DecoderSegment decoderSegment : tabHandle.decoderTab.getDecoderSegments()) {
                JsonObject segmentStateObject = new JsonObject();
                // Whether hex editor is selected
                segmentStateObject.addProperty("h", decoderSegment.hexRadio.isSelected());
                AbstractModificationMode mode = decoderSegment.modes.getSelectedMode();
                // Mode name
                segmentStateObject.addProperty("m", mode.getName());
                // Mode configurations
                segmentStateObject.add("c", mode.toJSON());
                // Add each segment state object to the segment state array
                segmentStateArray.add(segmentStateObject);
            }
            // Save the segment state array in tab state object
            tabStateObject.add("s", segmentStateArray);
            // Add each tab state object to the tab state array
            tabStateArray.add(tabStateObject);
        }
        extensionStateObject.addProperty("i", main.getSelectedIndex());
        extensionStateObject.add("t", tabStateArray);
        return extensionStateObject.toString();
    }

    // Decode the saved extension setting string and recover all tabs
    public void setState(String stateString, boolean initial) {
        if (stateString == null || stateString.isEmpty()) {
            if (initial) {
                addTab();
                main.setSelectedIndex(0);
                return;
            } else {
                throw new IllegalArgumentException("Error reading file or file is empty");
            }
        }
        try {
            int originalIndex = initial ? 0 : main.getSelectedIndex();
            int originalTabCount = main.getTabCount();
            JsonObject extensionStateObject = JsonParser.parseString(stateString).getAsJsonObject();
            JsonArray tabStateArray = extensionStateObject.get("t").getAsJsonArray();
            if (tabStateArray.size() == 0) {
                if (initial) {
                    addTab();
                    main.setSelectedIndex(0);
                }
                return;
            }
            for (int i = 0; i < tabStateArray.size(); i++) {
                JsonObject tabStateObject = tabStateArray.get(i).getAsJsonObject();
                // Build a new tab for each tab object
                addTab();
                DecoderTab dt = (DecoderTab) main.getComponentAt(originalTabCount + i - 1);
                dt.decoderTabHandle.tabName.setText(tabStateObject.get("n").getAsString());
                DecoderSegmentState dsState = dt.getDecoderSegments().get(0).dsState;
                dsState.setByteArrayList(Base64.getDecoder().decode(tabStateObject.get("b").getAsString()));
                JsonArray segmentStateArray = tabStateObject.getAsJsonArray("s");
                // Create (n - 1) new segments and update state for the 1..n-1 segments
                for (int j = 0; j < segmentStateArray.size() - 1; j++) {
                    dt.decoderSegments.get(j).addDecoderSegment();
                }
                // Update state for all segments
                for (int j = 0; j < dt.decoderSegments.size(); j++) {
                    dt.decoderSegments.get(j).updateEditors(dsState);
                }
                for (int j = 0; j < segmentStateArray.size(); j++) {
                    JsonObject segmentStateObject = segmentStateArray.get(j).getAsJsonObject();
                    DecoderSegment ds = dt.decoderSegments.get(j);
                    String modeName = segmentStateObject.get("m").getAsString();
                    JsonObject config = segmentStateObject.get("c").getAsJsonObject();
                    // If encoded as plain, do not "select" the item as it will create a new segment under the last one
                    if (!(modeName.equals(EncodeMode.NAME) && config.get("e").getAsString().equals(PlaintextEncoder.NAME))) {
                        ds.modes.setSelectedMode(modeName);
                        ds.modes.getSelectedMode().setFromJSON(config);
                    }
                    // Editor must be set at last to "force" the selection
                    if (segmentStateObject.get("h").getAsBoolean()) {
                        ds.displayHexEditor();
                    } else {
                        ds.displayTextEditor();
                    }
                }
            }
            main.setSelectedIndex(initial ? extensionStateObject.get("i").getAsInt() : originalIndex);
        } catch (Exception e) {
            if (initial) {
                addTab();
                main.setSelectedIndex(0);
                Logger.printErrorFromException(e);
            } else {
                throw e;
            }
        }
    }

    private static class DecoderTab extends JPanel {
        private DecoderTabHandle decoderTabHandle;
        private JScrollPane scrollingBodyHolder;
        private JPanel decoderTabBody;
        private ArrayList<DecoderSegment> decoderSegments;

        DecoderTab(String _title, MultiDecoderTab _parent) {
            decoderTabHandle = new DecoderTabHandle(_title, _parent, this);
            setupComponents();
        }

        void clear() {
            decoderSegments.forEach(x -> {
                x.dsState.clear();
            });
            decoderSegments.clear();
        }

        Component getTabHandleElement() {
            return decoderTabHandle;
        }

        ArrayList<DecoderSegment> getDecoderSegments() {
            return new ArrayList<>(decoderSegments);
        }

        private static class DecoderTabHandle extends JPanel {

            private MultiDecoderTab parent;
            private JTabbedPane parentTabbedPane;
            private DecoderTab decoderTab;
            private JTextField tabName;

            private DecoderTabHandle(String title, MultiDecoderTab multiDecoderTab, DecoderTab decoderTab) {
                this.decoderTab = decoderTab;
                this.parentTabbedPane = multiDecoderTab.getMain();
                this.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
                this.setOpaque(false);
                JLabel label = new JLabel(title);
                label.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
                tabName = new JTextField(title);
                tabName.setOpaque(false);
                tabName.setBorder(null);
                tabName.setBackground(new Color(0, 0, 0, 0));
                tabName.setEditable(false);
                tabName.setCaretColor(Color.BLACK);

                this.add(tabName);
                JButton closeButton = new JButton("✕");
                closeButton.setFont(new Font("monospaced", Font.PLAIN, 10));
                closeButton.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
                closeButton.setForeground(Color.GRAY);

                closeButton.setBorderPainted(false);
                closeButton.setContentAreaFilled(false);
                closeButton.setOpaque(false);

                tabName.addMouseListener(new MouseAdapter() {

                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (!parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                            parentTabbedPane.setSelectedComponent(decoderTab);
                            for (int i = 0; i < parentTabbedPane.getTabCount()-1; i++) {
                                if (!parentTabbedPane.getComponentAt(i).equals(decoderTab)) {
                                    DecoderTabHandle dth = (DecoderTabHandle) parentTabbedPane.getTabComponentAt(i);
                                    dth.tabName.setEditable(false);
                                }
                            }
                        } else {
                            tabName.setEditable(true);
                        }
                    }

                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (!parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                            parentTabbedPane.setSelectedComponent(decoderTab);
                            for (int i = 0; i < parentTabbedPane.getTabCount()-1; i++) {
                                if (!parentTabbedPane.getComponentAt(i).equals(decoderTab)) {
                                    DecoderTabHandle dth = (DecoderTabHandle) parentTabbedPane.getTabComponentAt(i);
                                    dth.tabName.setEditable(false);
                                }
                            }
                        } else {
                            tabName.setEditable(true);
                        }
                    }
                });

                closeButton.addActionListener(e -> {
                    multiDecoderTab.setTabChangeListenerLock(true);
                    if (parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                        if (parentTabbedPane.getTabCount() == 2) {
                            parentTabbedPane.remove(decoderTab);
                            //autoRepeaters.remove(autoRepeater);
                            multiDecoderTab.addTab();
                            multiDecoderTab.setTabChangeListenerLock(true);
                        } else if (parentTabbedPane.getTabCount() > 2) {
                            parentTabbedPane.remove(decoderTab);
                            //autoRepeaters.remove(autoRepeater);
                        }
                        decoderTab.clear();
                        if (parentTabbedPane.getSelectedIndex() == parentTabbedPane.getTabCount() - 1) {
                            parentTabbedPane.setSelectedIndex(parentTabbedPane.getTabCount() - 2);
                        }
                    } else {
                        parentTabbedPane.setSelectedComponent(decoderTab);
                    }
                    multiDecoderTab.setTabChangeListenerLock(false);
                });

                this.add(closeButton);
            }
        }

        private void setupComponents() {
            scrollingBodyHolder = new JScrollPane();
            decoderTabBody = new JPanel();
            decoderSegments = new ArrayList<>();
            decoderSegments.add(new DecoderSegment(this));
            this.setLayout(new BorderLayout());
            decoderTabBody.setLayout(new BoxLayout(decoderTabBody, BoxLayout.PAGE_AXIS));

            for (DecoderSegment decoderSegment : decoderSegments) {
                decoderTabBody.add(decoderSegment);
            }

            scrollingBodyHolder.setViewportView(decoderTabBody);
            this.add(scrollingBodyHolder, BorderLayout.CENTER);
        }

        private void updateDecoderSegments(int activeDecoderSegmentIndex) {
            // This goes through the entire list of decoder segments and updates all the ones
            // past the current one.
            for (int i = activeDecoderSegmentIndex; i < decoderSegments.size(); i++) {
                updateDecoderSegment(i);
            }
        }

        private void updateDecoderSegment(int activeDecoderSegmentIndex) {
            // If the item is at the end of the list there isn't anything to update
            // i.e. this prevents an array out of bounds error
            if (activeDecoderSegmentIndex >= decoderSegments.size() - 1) {
                return;
            }

            // Get the active segment
            DecoderSegment activeDecoderSegment = decoderSegments.get(activeDecoderSegmentIndex);

            // Get the current active tabs mode
            String selectedMode = (String) activeDecoderSegment.modeSelector.getSelectedItem();

            // This gets the next decoder segment
            DecoderSegment nextDecoderSegment = decoderSegments.get(activeDecoderSegmentIndex + 1);

            // Encode As... selected

            // Get the byte[] for the current decoder segment
            byte[] activeDsBytes = activeDecoderSegment.dsState.getByteArray();

            // Check to see if there was an error in the active decoder segment
            // If there was an error in a previous decoder segment propagate that to all following segments
            // Then change the text editor background red and display the error message
            if (activeDecoderSegment.hasError) {
                nextDecoderSegment.hasError = true;
                nextDecoderSegment.errorMessage = activeDecoderSegment.errorMessage;
                nextDecoderSegment.textEditor.setText(nextDecoderSegment.errorMessage);
                return;
            }

            //This code does all the byte modification
            try {
                nextDecoderSegment.dsState.setByteArrayList(activeDecoderSegment.modes.modifyBytes(activeDsBytes));
                nextDecoderSegment.updateEditors(nextDecoderSegment.dsState);
                try {
                    CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
                    decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
                    decoder.onMalformedInput(CodingErrorAction.REPORT);
                    decoder.decode(ByteBuffer.wrap(nextDecoderSegment.dsState.getByteArray()));
                    new String(nextDecoderSegment.dsState.getByteArray(), StandardCharsets.UTF_8);
                    // new UTF.newUTF8String(nextDecoderSegment.dsState.getByteArray());
                    //nextDecoderSegment.displayTextEditor(); // This is commented out as it sometimes got the extension frozen during loading settings, FIXME if anything wrong happens because of this
                } catch (Exception e) {
                    nextDecoderSegment.displayHexEditor();
                }
                nextDecoderSegment.hasError = false;
            } catch (ModificationException e) {
                nextDecoderSegment.errorMessage = e.getMessage();
                nextDecoderSegment.textEditor.setText(nextDecoderSegment.errorMessage);
                nextDecoderSegment.hasError = true;
            }
        }
    }

    private static class DecoderSegment extends JPanel {

        private DecoderTab parent;

        private DecoderSegmentState dsState;

        private JPanel radioPanel;

        // This changes the editor between hex view and text view
        private ButtonGroup textHexGroup;
        private JRadioButton textRadio;
        private JRadioButton hexRadio;
        private JComboBox<String> exportComboBox;

        // These manage the editor views
        private JPanel masterEditorPanel;

        // This managers cardLayouts
        private CardLayout cardManager;

        // These are all related to the editor views
        private CodeArea hexEditor;
        private JPanel controlPanel;
        private JScrollPane editorPanel;
        private JScrollPane hexPanel;

        private JTextPane textEditor;


        // This handles all the modes
        private ModificationModeManager modes;

        // These are the different types of tex box MODEs
        private JComboBox<String> modeSelector;

        // These are for showing an error message if improper decoding is going on.
        private String errorMessage;
        private boolean hasError;

        private boolean lockDocumentEvents;

        DecoderSegment(DecoderTab _parent) {
            parent = _parent;
            setupComponents();
        }

        private void addDecoderSegment() {
            int lastDsIndex = this.parent.decoderSegments.size();
            if (this.equals(this.parent.decoderSegments.get(lastDsIndex - 1))) {
                DecoderSegment ds = new DecoderSegment(parent);
                parent.decoderTabBody.add(Box.createRigidArea(new Dimension(0, 10)));
                parent.decoderSegments.add(ds);
                parent.decoderTabBody.add(ds);

                int thisIndex = parent.decoderSegments.indexOf(this);
                parent.updateDecoderSegment(thisIndex);
            }
        }

        JTextPane getTextEditor() {
            return textEditor;
        }

        // This function locks the text editor documentevents, calls textEditor.setText(), then unlocks the textEditor
        // to prevent setting the text from squashing the decoder segment state.

        void updateEditors(DecoderSegmentState dsState) {
            lockDocumentEvents = true;
            textEditor.setText(dsState.getDisplayString());
            hexEditor.setData(new ByteArrayEditableData(dsState.getByteArray()));
            lockDocumentEvents = false;
        }

        void displayHexEditor() {
            hexRadio.setSelected(true);
            cardManager.last(masterEditorPanel);
        }

        void displayTextEditor() {
            textRadio.setSelected(true);
            cardManager.last(masterEditorPanel);
            cardManager.first(masterEditorPanel);
        }

        void addActionListeners(JPanel panel) {
            DecoderSegment outsideThis = this;
            for (Component c : panel.getComponents()) {
                if (c instanceof JComboBox) {
                    ((JComboBox) c).addActionListener((ActionEvent e) -> {
                        int thisIndex = parent.decoderSegments.indexOf(this);
                        addDecoderSegment();
                        parent.updateDecoderSegments(thisIndex);
                    });
                } else if (c instanceof JPanel) {
                    addActionListeners((JPanel) c);
                } else if (c instanceof JTextField) {
                    ((JTextField) c).getDocument().addDocumentListener(new DocumentListener() {
                        @Override
                        public void insertUpdate(DocumentEvent e) {
                            int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                            addDecoderSegment();
                            parent.updateDecoderSegments(thisIndex);
                        }

                        @Override
                        public void removeUpdate(DocumentEvent e) {
                            int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                            addDecoderSegment();
                            parent.updateDecoderSegments(thisIndex);
                        }

                        // This doesn't do anything
                        @Override
                        public void changedUpdate(DocumentEvent e) {}
                    });
                }
            }
        }

        private void setupComponents() {
            // This manages the viewable state of a decoder segment
            dsState = new DecoderSegmentState();
            // This managers switching card view
            cardManager = new CardLayout();
            // This manages switching between hex editor and tex editor
            masterEditorPanel = new JPanel(cardManager);
            // This manages the different UIs for each mode selected in the dropdown

            modes = new ModificationModeManager();

            // Everything I initialize below this line is probably going to get removed
            textHexGroup = new ButtonGroup();
            editorPanel = new PDControlScrollPane();
            hexPanel = new JScrollPane();
            textEditor = new JTextPane();
            controlPanel = new JPanel();
            radioPanel = new JPanel();
            textRadio = new JRadioButton();
            hexRadio = new JRadioButton();
            exportComboBox = new JComboBox<>();

            modeSelector = new JComboBox<>();

            // Theses are the drop down labels

            hexEditor = new CodeArea();

            // "this" is the decoder segment
            this.setMaximumSize(new Dimension(3000, CONSTANTS.SEGMENT_HEIGHT));
            this.setMinimumSize(new Dimension(50, CONSTANTS.SEGMENT_HEIGHT));
            this.setPreferredSize(new Dimension(711, CONSTANTS.SEGMENT_HEIGHT));
            this.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 0));
            this.setLayout(new GridBagLayout());

            editorPanel.setMinimumSize(new Dimension(50, CONSTANTS.PANEL_HEIGHT));
            editorPanel.setPreferredSize(new Dimension(100, CONSTANTS.PANEL_HEIGHT));
            hexPanel.setMinimumSize(new Dimension(50, CONSTANTS.PANEL_HEIGHT));
            hexPanel.setPreferredSize(new Dimension(100, CONSTANTS.PANEL_HEIGHT));
            // hexEditor has its own vertical scrollbar
            hexPanel.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);

            textEditor.setMinimumSize(new Dimension(50, CONSTANTS.PANEL_HEIGHT));
            textEditor.setPreferredSize(new Dimension(100, CONSTANTS.PANEL_HEIGHT));
            textEditor.setContentType("text/plain");
            textEditor.setComponentPopupMenu(MenuHandler.createTextEditorPopupMenu(textEditor, this));

            hexEditor.setMinimumSize(new Dimension(50, CONSTANTS.PANEL_HEIGHT));
            hexEditor.setPreferredSize(new Dimension(100, CONSTANTS.PANEL_HEIGHT));
            hexEditor.setComponentPopupMenu(MenuHandler.createHexEditorPopupMenu(hexEditor, this));

            hexPanel.setViewportView(hexEditor);
            editorPanel.setViewportView(textEditor);
            GridBagConstraints editorPanelConstraints = new GridBagConstraints();
            editorPanelConstraints.fill = GridBagConstraints.HORIZONTAL;
            editorPanelConstraints.anchor = GridBagConstraints.WEST;
            editorPanelConstraints.weightx = 1.0;

            masterEditorPanel.add(editorPanel);
            masterEditorPanel.add(hexPanel);

            this.add(masterEditorPanel, editorPanelConstraints);
            controlPanel.setMaximumSize(new Dimension(150, CONSTANTS.PANEL_HEIGHT));
            controlPanel.setMinimumSize(new Dimension(150, CONSTANTS.PANEL_HEIGHT));
            controlPanel.setPreferredSize(new Dimension(150, CONSTANTS.PANEL_HEIGHT));
            controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.PAGE_AXIS));

            // Radio group
            radioPanel.setMaximumSize(new Dimension(125, CONSTANTS.COMBO_BOX_HEIGHT));
            radioPanel.setMinimumSize(new Dimension(125, CONSTANTS.COMBO_BOX_HEIGHT));
            radioPanel.setPreferredSize(new Dimension(125, CONSTANTS.COMBO_BOX_HEIGHT));
            radioPanel.setLayout(new GridLayout());

            textRadio.setText("Text");
            textRadio.setSelected(true);
            textRadio.putClientProperty("JComponent.sizeVariant", "small");
            textRadio.setHorizontalAlignment(AbstractButton.CENTER);

            hexRadio.setText("Hex");
            hexRadio.putClientProperty("JComponent.sizeVariant", "small");
            hexRadio.setHorizontalAlignment(AbstractButton.CENTER);

            textHexGroup.add(textRadio);
            textHexGroup.add(hexRadio);

            radioPanel.add(textRadio);
            radioPanel.add(hexRadio);
            controlPanel.add(radioPanel);

            // Modes
            controlPanel.add(modes.getUI());

            // Export combo box
            exportComboBox.setMaximumSize(CONSTANTS.COMBO_BOX_DIMENSION);
            exportComboBox.setMinimumSize(CONSTANTS.COMBO_BOX_DIMENSION);
            exportComboBox.setPreferredSize(CONSTANTS.COMBO_BOX_DIMENSION);
            exportComboBox.addItem("Save as...");
            exportComboBox.addItem("Raw Data");
            exportComboBox.addItem("Hex");
            exportComboBox.addItem("UTF-8 String");

            controlPanel.add(exportComboBox);

            GridBagConstraints controlPanelConstraints = new GridBagConstraints();

            this.add(controlPanel, controlPanelConstraints);

            // Actionlisteners go here
            hexRadio.addActionListener((ActionEvent e) -> {
                updateEditors(dsState);
                cardManager.last(masterEditorPanel);
            });

            textRadio.addActionListener((ActionEvent e) -> {
                updateEditors(dsState);
                cardManager.first(masterEditorPanel);
            });

            exportComboBox.addActionListener((ActionEvent event) -> {
                if (exportComboBox.getSelectedIndex() == 0) {
                    return;
                }
                try {
                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setDialogTitle("Save " + ((String) exportComboBox.getSelectedItem()).toUpperCase() + " to...");
                    // Grab focus to save file dialog
                    fileChooser.addHierarchyListener((_event)-> {
                        grabFocus();
                    });
                    if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                        FileOutputStream fileOutputStream = new FileOutputStream(fileChooser.getSelectedFile());
                        switch (exportComboBox.getSelectedIndex()) {
                            case 1:
                                fileOutputStream.write(dsState.getByteArray());
                                break;
                            case 2:
                                fileOutputStream.write(Utils.convertByteArrayToHexString(dsState.getByteArray()).getBytes());
                                break;
                            case 3:
                                fileOutputStream.write(dsState.getDisplayString().getBytes());
                                break;
                        }
                        fileOutputStream.close();
                    }
                } catch (Exception ee) {
                    Logger.printErrorFromException(ee);
                }
                exportComboBox.setSelectedIndex(0);
            });

            // add action listeners
            addActionListeners(modes.getUI());
            for (AbstractModificationMode mode : modes.getModes()) {
                addActionListeners(mode.getUI());
            }

            // This is where all the encoding and decoding happens
            DecoderSegment outsideThis = this;

            //update dsstate whenever the hexeditor is updated.
            hexEditor.addDataChangedListener(new DataChangedListener() {
                @Override
                public void dataChanged() {
                    if (!lockDocumentEvents) {
                        dsState.setByteArrayList(Utils.convertHexDataToByteArray(hexEditor.getData()));
                        int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                        parent.updateDecoderSegments(thisIndex);
                    }
                }
            });

            textEditor.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    if (! lockDocumentEvents) {
                        // These events trigger when a user is doing regular typing into the text editor
                        String insertedText = textEditor.getText().replace("\r\n", "\n").substring(e.getOffset(), e.getOffset() + e.getLength());
                        dsState.insertUpdateIntoByteArrayList(insertedText, e.getOffset());

                        // Utils.printByteArray(dsState.getByteArray());

                        int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                        parent.updateDecoderSegments(thisIndex);

                        SwingUtilities.invokeLater(() -> {
                            int caretPos = textEditor.getCaretPosition();
                            lockDocumentEvents = true;
                            textEditor.setText(dsState.getDisplayString());
                            lockDocumentEvents = false;
                            textEditor.setCaretPosition(caretPos);
                        });
                    }
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    if (!lockDocumentEvents) {
                        dsState.removeUpdateFromByteArrayList(e.getOffset(), e.getLength());
                        // Utils.printByteArray(dsState.getByteArray());

                        int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                        parent.updateDecoderSegments(thisIndex);

                        SwingUtilities.invokeLater(() -> {
                            int caretPos = textEditor.getCaretPosition();
                            lockDocumentEvents = true;
                            textEditor.setText(dsState.getDisplayString());
                            lockDocumentEvents = false;
                            textEditor.setCaretPosition(caretPos);
                        });
                    }
                }

                // This doesn't do anything
                // It only fires when the text mode of the document changes which never happens
                @Override
                public void changedUpdate(DocumentEvent e) { }
            });
        }
    }

    private static class MenuHandler {

        private static final int META_MASK = java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();

        private static final String UNDO_ACTION_NAME = "Undo";
        private static final String REDO_ACTION_NAME = "Redo";

        private static final String CUT_ACTION_NAME = "Cut";
        private static final String COPY_ACTION_NAME = "Copy";
        private static final String PASTE_ACTION_NAME = "Paste";
        private static final String DELETE_ACTION_NAME = "Delete";
        private static final String SELECT_ALL_ACTION_NAME = "Select All";

        private static JPopupMenu createHexEditorPopupMenu(final CodeArea codeArea, final DecoderSegment decoderSegment) {
            JPopupMenu popupMenu = new JPopupMenu();

            // Undo popup menu item
            final JMenuItem undoPopupMenuItem = new JMenuItem();
            AbstractAction undoAction = new AbstractAction(UNDO_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    decoderSegment.dsState.undo();
                    SwingUtilities.invokeLater(() -> {
                        int thisIndex = decoderSegment.parent.decoderSegments.indexOf(decoderSegment);
                        decoderSegment.parent.updateDecoderSegments(thisIndex);
                        decoderSegment.updateEditors(decoderSegment.dsState);
                    });
                }
            };
            codeArea.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, META_MASK), "undo");
            codeArea.getActionMap().put("undo", undoAction);
            undoPopupMenuItem.setAction(undoAction);
            popupMenu.add(undoPopupMenuItem);

            // Redo popup menu item
            final JMenuItem redoPopupMenuItem = new JMenuItem();
            AbstractAction redoAction = new AbstractAction(REDO_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    decoderSegment.dsState.redo();
                    SwingUtilities.invokeLater(() -> {
                        int thisIndex = decoderSegment.parent.decoderSegments.indexOf(decoderSegment);
                        decoderSegment.parent.updateDecoderSegments(thisIndex);
                        decoderSegment.updateEditors(decoderSegment.dsState);
                    });
                }
            };
            codeArea.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, META_MASK | InputEvent.SHIFT_DOWN_MASK), "redo");
            codeArea.getActionMap().put("redo", redoAction);
            redoPopupMenuItem.setAction(redoAction);
            popupMenu.add(redoPopupMenuItem);

            popupMenu.addSeparator();

            final ButtonGroup codeTypeButtonGroup = new ButtonGroup();

            JMenu viewMenu = new JMenu("View");

            final JCheckBoxMenuItem showUnprintableMenuItem = new JCheckBoxMenuItem("Unprintable Characters");
            showUnprintableMenuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.setShowUnprintableCharacters(!codeArea.isShowUnprintableCharacters());
                }
            });
            viewMenu.add(showUnprintableMenuItem);

            final JCheckBoxMenuItem wrappingModeMenuItem = new JCheckBoxMenuItem("Wrapping mode");
            wrappingModeMenuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.setWrapMode(!codeArea.isWrapMode());
                }
            });
            viewMenu.add(wrappingModeMenuItem);

            popupMenu.add(viewMenu);

            JMenu codeTypeMenu = new JMenu("Code Type");
            final JRadioButtonMenuItem binaryCodeTypeMenuItem = new JRadioButtonMenuItem("Binary");
            binaryCodeTypeMenuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.setCodeType(CodeType.BINARY);
                }
            });
            codeTypeButtonGroup.add(binaryCodeTypeMenuItem);
            codeTypeMenu.add(binaryCodeTypeMenuItem);

            final JRadioButtonMenuItem octalCodeTypeMenuItem = new JRadioButtonMenuItem("Octal");
            octalCodeTypeMenuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.setCodeType(CodeType.OCTAL);
                }
            });
            codeTypeButtonGroup.add(octalCodeTypeMenuItem);
            codeTypeMenu.add(octalCodeTypeMenuItem);

            final JRadioButtonMenuItem decimalCodeTypeMenuItem = new JRadioButtonMenuItem("Decimal");
            decimalCodeTypeMenuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.setCodeType(CodeType.DECIMAL);
                }
            });
            codeTypeButtonGroup.add(decimalCodeTypeMenuItem);
            codeTypeMenu.add(decimalCodeTypeMenuItem);

            final JRadioButtonMenuItem hexaCodeTypeMenuItem = new JRadioButtonMenuItem("Hexadecimal");
            hexaCodeTypeMenuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.setCodeType(CodeType.HEXADECIMAL);
                }
            });
            codeTypeButtonGroup.add(hexaCodeTypeMenuItem);
            codeTypeMenu.add(hexaCodeTypeMenuItem);

            popupMenu.add(codeTypeMenu);
            popupMenu.addSeparator();

            final JMenuItem editCutPopupMenuItem = new JMenuItem();
            AbstractAction cutAction = new AbstractAction(CUT_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.cut();
                }
            };
            editCutPopupMenuItem.setAction(cutAction);
            popupMenu.add(editCutPopupMenuItem);

            final JMenuItem editCopyPopupMenuItem = new JMenuItem();
            AbstractAction copyAction = new AbstractAction(COPY_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.copy();
                }
            };
            editCopyPopupMenuItem.setAction(copyAction);
            popupMenu.add(editCopyPopupMenuItem);

            final JMenuItem editPastePopupMenuItem = new JMenuItem();
            AbstractAction pasteAction = new AbstractAction(PASTE_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.paste();
                }
            };
            editPastePopupMenuItem.setAction(pasteAction);
            popupMenu.add(editPastePopupMenuItem);

            final JMenuItem editDeletePopupMenuItem = new JMenuItem();
            AbstractAction deleteAction = new AbstractAction(DELETE_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.delete();
                }
            };
            editDeletePopupMenuItem.setAction(deleteAction);
            popupMenu.add(editDeletePopupMenuItem);

            final JMenuItem selectAllPopupMenuItem = new JMenuItem();
            AbstractAction selectAllAction = new AbstractAction(SELECT_ALL_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    codeArea.selectAll();
                }
            };
            selectAllPopupMenuItem.setAction(selectAllAction);
            popupMenu.add(selectAllPopupMenuItem);
            popupMenu.addSeparator();

            JMenuItem changeEncoding = new JMenuItem();
            changeEncoding.setAction(new AbstractAction("Change Encoding...") {
                @Override
                public void actionPerformed(ActionEvent e) {
                    Window windowAncestor = SwingUtilities.getWindowAncestor(codeArea);
                    JFrame frame = windowAncestor instanceof JFrame ? (JFrame) windowAncestor : null;
                    EncodingSelectionDialog encodingSelectionDialog = new EncodingSelectionDialog(frame, true);
                    encodingSelectionDialog.setEncoding(codeArea.getCharset().name());
                    encodingSelectionDialog.setVisible(true);
                    if (encodingSelectionDialog.getReturnStatus() == EncodingSelectionDialog.RET_OK) {
                        codeArea.setCharset(Charset.forName(encodingSelectionDialog.getEncoding()));
                    }
                }
            });
            popupMenu.add(changeEncoding);

            popupMenu.addPopupMenuListener(new PopupMenuListener() {
                @Override
                public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                    undoPopupMenuItem.setEnabled(decoderSegment.dsState.canUndo());
                    redoPopupMenuItem.setEnabled(decoderSegment.dsState.canRedo());

                    editCutPopupMenuItem.setEnabled(codeArea.hasSelection());
                    editCopyPopupMenuItem.setEnabled(codeArea.hasSelection());
                    editDeletePopupMenuItem.setEnabled(codeArea.hasSelection());
                    editPastePopupMenuItem.setEnabled(codeArea.canPaste());

                    CodeType codeType = codeArea.getCodeType();
                    switch (codeType) {
                        case BINARY: {
                            binaryCodeTypeMenuItem.setSelected(true);
                            break;
                        }
                        case OCTAL: {
                            octalCodeTypeMenuItem.setSelected(true);
                            break;
                        }
                        case DECIMAL: {
                            decimalCodeTypeMenuItem.setSelected(true);
                            break;
                        }
                        case HEXADECIMAL: {
                            hexaCodeTypeMenuItem.setSelected(true);
                            break;
                        }
                    }

                    showUnprintableMenuItem.setSelected(codeArea.isShowUnprintableCharacters());
                    wrappingModeMenuItem.setSelected(codeArea.isWrapMode());
                }

                @Override
                public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                }

                @Override
                public void popupMenuCanceled(PopupMenuEvent e) {
                }
            });

            return popupMenu;
        }

        private static JPopupMenu createTextEditorPopupMenu(final JTextPane textEditor, final DecoderSegment decoderSegment) {
            JPopupMenu popupMenu = new JPopupMenu();

            // Undo popup menu item
            final JMenuItem undoPopupMenuItem = new JMenuItem();
            AbstractAction undoAction = new AbstractAction(UNDO_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    decoderSegment.dsState.undo();
                    SwingUtilities.invokeLater(() -> {
                        int thisIndex = decoderSegment.parent.decoderSegments.indexOf(decoderSegment);
                        decoderSegment.parent.updateDecoderSegments(thisIndex);
                        decoderSegment.updateEditors(decoderSegment.dsState);
                    });
                }
            };
            textEditor.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, META_MASK), "undo");
            textEditor.getActionMap().put("undo", undoAction);
            undoPopupMenuItem.setAction(undoAction);
            popupMenu.add(undoPopupMenuItem);

            // Redo popup menu item
            final JMenuItem redoPopupMenuItem = new JMenuItem();
            AbstractAction redoAction = new AbstractAction(REDO_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    decoderSegment.dsState.redo();
                    SwingUtilities.invokeLater(() -> {
                        int thisIndex = decoderSegment.parent.decoderSegments.indexOf(decoderSegment);
                        decoderSegment.parent.updateDecoderSegments(thisIndex);
                        decoderSegment.updateEditors(decoderSegment.dsState);
                    });
                }
            };
            textEditor.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, META_MASK | InputEvent.SHIFT_DOWN_MASK), "redo");
            textEditor.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, META_MASK), "redo");
            textEditor.getActionMap().put("redo", redoAction);
            redoPopupMenuItem.setAction(redoAction);
            popupMenu.add(redoPopupMenuItem);

            popupMenu.addSeparator();

            final JMenuItem editCutPopupMenuItem = new JMenuItem();
            AbstractAction cutAction = new AbstractAction(CUT_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    textEditor.cut();
                }
            };
            editCutPopupMenuItem.setAction(cutAction);
            popupMenu.add(editCutPopupMenuItem);

            final JMenuItem editCopyPopupMenuItem = new JMenuItem();
            AbstractAction copyAction = new AbstractAction(COPY_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    textEditor.copy();
                }
            };
            editCopyPopupMenuItem.setAction(copyAction);
            popupMenu.add(editCopyPopupMenuItem);

            final JMenuItem editPastePopupMenuItem = new JMenuItem();
            AbstractAction pasteAction = new AbstractAction(PASTE_ACTION_NAME) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    textEditor.paste();
                }
            };
            editPastePopupMenuItem.setAction(pasteAction);
            popupMenu.add(editPastePopupMenuItem);

            popupMenu.addPopupMenuListener(new PopupMenuListener() {
                @Override
                public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                    undoPopupMenuItem.setEnabled(decoderSegment.dsState.canUndo());
                    redoPopupMenuItem.setEnabled(decoderSegment.dsState.canRedo());

                    boolean hasSelection = textEditor.getSelectionEnd() > textEditor.getSelectionStart();
                    // TODO detect
                    boolean pasteAvailable = true;
                    editCutPopupMenuItem.setEnabled(hasSelection);
                    editCopyPopupMenuItem.setEnabled(hasSelection);
                    editPastePopupMenuItem.setEnabled(pasteAvailable);
                }

                @Override
                public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                }

                @Override
                public void popupMenuCanceled(PopupMenuEvent e) {
                }
            });

            return popupMenu;
        }
    }
}