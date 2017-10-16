package trust.nccgroup.decoderimproved;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;

import com.google.common.collect.Lists;
import util.PDControlScrollPane;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.deltahex.DataChangedListener;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.event.*;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.ArrayList;

public class MultiDecoderTab extends JPanel implements ITab {

    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private JTabbedPane main;
    private JPanel newTabButton;

    boolean tabChangeListenerLock = false;

    //Plugin starts with one decoder tab open and the "new tab" tab
    private int overallCount = 0;

    public boolean isTabChangeListenerLock() {
        return tabChangeListenerLock;
    }

    public void setTabChangeListenerLock(boolean tabChangeListenerLock) {
        this.tabChangeListenerLock = tabChangeListenerLock;
    }

    public MultiDecoderTab(IBurpExtenderCallbacks _callbacks) {
        // Set main tab layout
        setLayout(new BorderLayout());
        //initialize ui elements
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        main = new JTabbedPane();

        // Add "new tab" tab
        newTabButton = new JPanel();
        newTabButton.setName("...");
        main.add(newTabButton);

        // Add initial decoder tab
        this.addTab();

        main.setSelectedIndex(0);

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
            for (int i = 0; i < main.getTabCount()-1; i++) {
                //DecoderTab.DecoderTabHandle dth = (DecoderTab.DecoderTabHandle) main.getTabComponentAt(i);
                //dth.tabName.setEditable(false);
            }

        });
        add(main, BorderLayout.CENTER);
    }

    // Logic for adding new tabs
    public void addTab() {
        tabChangeListenerLock = true;
        // Add a new tab
        overallCount += 1;
        DecoderTab mt2 = new DecoderTab(Integer.toString(overallCount, 10), this);
        callbacks.customizeUiComponent(mt2);
        main.add(mt2);
        main.setTabComponentAt(main.indexOfComponent(mt2), mt2.getTabHandleElement());
        main.setSelectedComponent(mt2);
        mt2.getDecoderSegments().get(0).getTextEditor().requestFocus();

        // This moves the '...' tab to the end of the tab list
        main.remove(newTabButton);
        main.add(newTabButton);
        tabChangeListenerLock = false;
    }

    public int firstEmptyDecoder() {
        if (main.getComponentAt(main.getTabCount()-2) instanceof DecoderTab) {
            DecoderTab dt = (DecoderTab) main.getComponentAt(main.getTabCount()-2);
            if (dt.getDecoderSegments().get(0).dsState.getDisplayString().equals("")) {
                return main.getTabCount() - 2;
            }
        }
        return -1;
    }

    public void receiveTextFromMenu(String selectedText) {
        // TODO: Add checks to see if the decoder segment is populated.
        byte[] selectedTextBytes;
        try {
            selectedTextBytes = selectedText.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // This should never happen
            selectedTextBytes = new byte[0];
        }
        if (firstEmptyDecoder() == -1) {
            // Add a new tab

            addTab();
            DecoderTab dt = (DecoderTab) main.getComponentAt(main.getTabCount()-2);
            dt.getDecoderSegments().get(0).dsState.setByteArrayList(selectedTextBytes);
            dt.updateDecoderSegments(0);
            for (DecoderSegment ds : dt.getDecoderSegments()) {
                ds.updateEditors(dt.getDecoderSegments().get(0).dsState);
            }
            //overallCount += 1;
            //DecoderTab mt2 = new DecoderTab(Integer.toString(overallCount, 10), this);
            //mt2.decoderSegments.get(0).dsState.setByteArrayList(selectedTextBytes);
            //mt2.decoderSegments.get(0).updateEditors(mt2.decoderSegments.get(0).dsState);
            //callbacks.customizeUiComponent(mt2);
            //main.add(mt2);
            //main.setTabComponentAt(main.indexOfComponent(mt2), mt2.getTabHandleElement());
            //main.setSelectedComponent(mt2);
            //// This moves the '...' tab to the end of the tab list
            //main.remove(newTabButton);
            //main.add(newTabButton);
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

    public JTabbedPane getMain() { return main; }

    private static class DecoderTab extends JPanel {
        private DecoderTabHandle decoderTabHandle;
        private JScrollPane scrollingBodyHolder;
        private JPanel decoderTabBody;
        private ArrayList<DecoderSegment> decoderSegments;

        public DecoderTab(String _title, MultiDecoderTab _parent) {
            decoderTabHandle = new DecoderTabHandle(_title, _parent, this);
            _parent.callbacks.customizeUiComponent(decoderTabHandle);
            setupComponents();
        }

        public Component getTabHandleElement() {
            return decoderTabHandle;
        }

        public ArrayList<DecoderSegment> getDecoderSegments() {
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
                    public void mouseClicked(MouseEvent e) {
                        if (!parentTabbedPane.getSelectedComponent().equals(decoderTab)) {
                            parentTabbedPane.setSelectedComponent(decoderTab);
                            for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
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
            decoderSegments = Lists.newArrayList(new DecoderSegment(this));
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
                    CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder();
                    decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
                    decoder.onMalformedInput(CodingErrorAction.REPORT);
                    decoder.decode(ByteBuffer.wrap(nextDecoderSegment.dsState.getByteArray()));
                    new String(nextDecoderSegment.dsState.getByteArray(), "UTF-8");
                    // new UTF.newUTF8String(nextDecoderSegment.dsState.getByteArray());
                    nextDecoderSegment.displayTextEditor();
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

        public DecoderSegment(DecoderTab _parent) {
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

        public JTextPane getTextEditor() {
            return textEditor;
        }

        // This function locks the text editor documentevents, calls textEditor.setText(), then unlocks the textEditor
        // to prevent setting the text from squashing the decoder segment state.

        public void updateEditors(DecoderSegmentState dsState) {
            lockDocumentEvents = true;
            textEditor.setText(dsState.getDisplayString());
            hexEditor.setData(new ByteArrayEditableData(dsState.getByteArray()));
            lockDocumentEvents = false;
        }

        public void displayHexEditor() {
            hexRadio.setSelected(true);
            cardManager.last(masterEditorPanel);
        }

        public void displayTextEditor() {
            textRadio.setSelected(true);
            cardManager.last(masterEditorPanel);
            cardManager.first(masterEditorPanel);
        }

        public void addActionListeners(JPanel panel) {
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

            modeSelector = new JComboBox<>();

            // Theses are the drop down labels

            hexEditor = new CodeArea();

            this.setLayout(new BorderLayout());
            {
                this.setMaximumSize(new Dimension(3000, 150));
                this.setMinimumSize(new Dimension(500, 133));
                this.setPreferredSize(new Dimension(711, 200));
                this.setSize(new Dimension(100, 200));
                this.setLayout(new GridBagLayout());
                {
                    editorPanel.setMinimumSize(new Dimension(100, 150));
                    editorPanel.setPreferredSize(new Dimension(100, 150));

                    hexPanel.setMinimumSize(new Dimension(100, 150));
                    hexPanel.setPreferredSize(new Dimension(100, 150));
                    {
                        textEditor.setMinimumSize(new Dimension(50, 150));
                        textEditor.setSize(new Dimension(100, 80));
                        textEditor.setContentType("text/plain");

                        hexEditor.setMinimumSize(new Dimension(50, 150));
                        hexEditor.setSize(new Dimension(100, 80));
                    }
                    hexPanel.setViewportView(hexEditor);
                    editorPanel.setViewportView(textEditor);
                }
                GridBagConstraints editorPanelConstraints = new GridBagConstraints();
                editorPanelConstraints.fill = GridBagConstraints.HORIZONTAL;
                editorPanelConstraints.anchor = GridBagConstraints.WEST;
                editorPanelConstraints.weightx = 1.0;

                masterEditorPanel.add(editorPanel);
                masterEditorPanel.add(hexPanel);

                this.add(masterEditorPanel, editorPanelConstraints);
                {
                    controlPanel.setMaximumSize(new Dimension(2100, 150));
                    controlPanel.setMinimumSize(new Dimension(2100, 150));
                    controlPanel.setPreferredSize(new Dimension(150, 150));
                    controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.PAGE_AXIS));
                    {
                        radioPanel.setMaximumSize(new Dimension(125, 25));
                        radioPanel.setMinimumSize(new Dimension(125, 25));
                        radioPanel.setPreferredSize(new Dimension(125, 25));
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
                    }
                    controlPanel.add(radioPanel);

                    controlPanel.add(modes.getUI());

                }
            }
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

            // add action listeners
            addActionListeners(modes.getUI());
            for (ModificationMode mode : modes.getModes()) {
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
                        String insertedText = textEditor.getText().substring(e.getOffset(), e.getOffset() + e.getLength());
                        dsState.insertUpdateIntoByteArrayList(insertedText, e.getOffset());

                        // Utils.printByteArray(dsState.getByteArray());

                        int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                        parent.updateDecoderSegments(thisIndex);
                    }
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    if (!lockDocumentEvents) {
                        dsState.removeUpdateFromByteArrayList(e.getOffset(), e.getLength());
                        // Utils.printByteArray(dsState.getByteArray());

                        int thisIndex = parent.decoderSegments.indexOf(outsideThis);
                        parent.updateDecoderSegments(thisIndex);
                    }
                }

                // This doesn't do anything
                // It only fires when the text mode of the document changes which never happens
                @Override
                public void changedUpdate(DocumentEvent e) { }
            });
        }
    }
}