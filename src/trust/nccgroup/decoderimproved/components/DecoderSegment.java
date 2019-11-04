package trust.nccgroup.decoderimproved.components;

import org.exbin.deltahex.CodeType;
import org.exbin.deltahex.DataChangedListener;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import trust.nccgroup.decoderimproved.*;
import trust.nccgroup.decoderimproved.modes.AbstractModificationMode;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

public class DecoderSegment extends JPanel {

    private DecoderTab parent;

    public DecoderSegmentState dsState;

    private JPanel radioPanel;

    // This changes the editor between hex view and text view
    private ButtonGroup textHexGroup;
    private JRadioButton textRadio;
    public JRadioButton hexRadio;
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

    JTextPane textEditor;


    // This handles all the modes
    public ModificationModeManager modes;

    // These are the different types of tex box MODEs
    JComboBox<String> modeSelector;

    // These are for showing an error message if improper decoding is going on.
    String errorMessage;
    boolean hasError;

    private boolean lockDocumentEvents;

    DecoderSegment(DecoderTab _parent) {
        parent = _parent;
        setupComponents();
    }

    void addDecoderSegment() {
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
        if (!hasError) {
            SwingUtilities.invokeLater(() -> {
                hexRadio.setSelected(true);
                cardManager.last(masterEditorPanel);
            });
        } else {
            textRadio.setSelected(true);
        }
    }

    void displayTextEditor() {
        SwingUtilities.invokeLater(() -> {
            textRadio.setSelected(true);
            cardManager.first(masterEditorPanel);
        });
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
            if (!hasError) {
                updateEditors(dsState);
                cardManager.last(masterEditorPanel);
            } else {
                textRadio.setSelected(true);
            }
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

    static class DecoderSegmentState {
        // I'm going to back this thing with an arraylist for now
        // This is going to get changed to a rope or a data structure that's better
        // for text editors in the future.
        // autoboxing makes me sad
        private final int UNDO_LIMIT = 10;
        private final int REDO_LIMIT = 10;
        private enum Action {
            INSERT, REMOVE, REPLACE
        }

        private ArrayList<Byte> byteArrayList;
        private ArrayDeque<Command> undoDeque;
        private ArrayDeque<Command> redoDeque;

        DecoderSegmentState() {
            byteArrayList = new ArrayList<>();
            undoDeque = new ArrayDeque<>();
            redoDeque = new ArrayDeque<>();
        }

        void clear() {
            byteArrayList.clear();
            undoDeque.clear();
            redoDeque.clear();
        }

        int getByteSize() {
            return byteArrayList.size();
        }

        String getDisplayString() {
            return UTF8StringEncoder.newUTF8String(getByteArray());
        }

        byte[] getByteArray() {
            return Utils.convertByteArrayListToByteArray(byteArrayList);
        }

        void setByteArrayList(byte[] data) {
            undoDeque.addLast(new Command(Action.REPLACE, getByteArray(), -1));
            redoDeque.clear();
            resizeDeques();
            replaceBytes(data);
        }

        // Calculate byte offset based on UTF-8 multibyte definition, to support more multibyte characters.
        private int calculateByteOffset(int stringOffset) {
            int offset = 0;
            for (int i = 0; i < stringOffset; i++) {
                int cur = offset;
                if (cur >= byteArrayList.size())
                    break;
                byte b = byteArrayList.get(cur);
                int expectedLength = Utils.multibyteExpectLength(b);
                switch (expectedLength) {
                    case 1: // single-byte char, in 00000000 - 01111111
                        if (b == 13 && cur + 1 < byteArrayList.size() && byteArrayList.get(cur + 1) == 10) { // CRLF \x0d\x0a case
                            offset += 2;
                        } else {
                            offset += 1;
                        }
                        break;
                    case 2: // two-byte char, first byte in 11000000 - 11011111
                    case 3: // three-byte char, first byte in 11100000 - 11101111
                    case 4: // four-byte char, first byte in 11110000 - 11110111
                        offset += multibyteOffset(cur, expectedLength);
                        break;
                    default:
                        offset += 1;
                        break;
                }
            }
            return offset;
        }

        private int multibyteOffset(int currentOffset, int maxLength) {
            int byteCount = 0;
            List<Byte> buf = new ArrayList<>();
            for (int i = 0; i < maxLength; i++) {
                // the second (or third and fourth) byte should be in 10000000 - 10111111
                if (currentOffset + i < byteArrayList.size() && (i == 0 || byteArrayList.get(currentOffset + i) <= -65)) {
                    byteCount += 1;
                    buf.add(byteArrayList.get(currentOffset + i));
                } else {
                    break;
                }
            }
            int characterCount = UTF8StringEncoder.newUTF8String(Utils.convertByteArrayListToByteArray(buf)).length();
            return byteCount - characterCount + 1;
        }

        // This is for when the text editor is updating the decoder segment state
        void insertUpdateIntoByteArrayList(String input, int offset) {
            // I turn the input string into bytes so I can correctly input all the bytes
            // then I add those bytes to byteArrayList
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            int inputOffset = calculateByteOffset(offset);
            insertBytes(inputBytes, inputOffset);
            undoDeque.addLast(new Command(Action.INSERT, inputBytes, inputOffset));
            redoDeque.clear();
            resizeDeques();
        }

        // This is for when the text editor is removing characters from the byteArrayList
        void removeUpdateFromByteArrayList(int offset, int length) {
            // So this chunk of code gets the substring that was removed
            // I then turn that into bytes so i know how many bytes needs to be removed
            // to keep this update in sync with byteArrayList
            // try {
            // I need to calculate the correct offsets based on the actual underlying bytes
            int deleteOffset = calculateByteOffset(offset);
            int charsRemovedLength = calculateByteOffset(offset + length) - deleteOffset;
            byte[] removedBytes = removeBytes(deleteOffset, charsRemovedLength);
            undoDeque.addLast(new Command(Action.REMOVE, removedBytes, deleteOffset));
            redoDeque.clear();
            resizeDeques();
        }

        private void insertBytes(byte[] bytes, int offset) {
            for (int i = 0; i < bytes.length; i++) {
                byteArrayList.add(i + offset, bytes[i]);
            }
        }

        private byte[] removeBytes(int offset, int length) {
            byte[] removedBytes = new byte[length];
            for (int i = 0; i < length; i++) {
                removedBytes[i] = byteArrayList.remove(offset);
            }
            return removedBytes;
        }

        private void replaceBytes(byte[] bytes) {
            byteArrayList.clear();
            for (int i = 0; i < bytes.length; i++) {
                byteArrayList.add(bytes[i]);
            }
        }

        boolean canUndo() {
            return undoDeque.size() > 0;
        }

        boolean canRedo() {
            return redoDeque.size() > 0;
        }

        void undo() {
            if (!undoDeque.isEmpty()) {
                Command undoCommand = undoDeque.removeLast();
                switch (undoCommand.action) {
                    case INSERT:
                        removeBytes(undoCommand.offset, undoCommand.diff.length);
                        break;
                    case REMOVE:
                        insertBytes(undoCommand.diff, undoCommand.offset);
                        break;
                    case REPLACE:
                        byte[] swapDiff = getByteArray();
                        replaceBytes(undoCommand.diff);
                        undoCommand.diff = swapDiff;
                        break;
                    default:
                        break;
                }
                redoDeque.addLast(undoCommand);
                resizeDeques();
            }
        }

        void redo() {
            if (!redoDeque.isEmpty()) {
                Command redoCommand = redoDeque.removeLast();
                switch (redoCommand.action) {
                    case INSERT:
                        insertBytes(redoCommand.diff, redoCommand.offset);
                        break;
                    case REMOVE:
                        removeBytes(redoCommand.offset, redoCommand.diff.length);
                        break;
                    case REPLACE:
                        byte[] swapDiff = getByteArray();
                        replaceBytes(redoCommand.diff);
                        redoCommand.diff = swapDiff;
                        break;
                    default:
                        break;
                }
                undoDeque.addLast(redoCommand);
                resizeDeques();
            }
        }

        private void resizeDeques() {
            while (undoDeque.size() > UNDO_LIMIT) {
                undoDeque.removeFirst();
            }
            while (redoDeque.size() > REDO_LIMIT) {
                redoDeque.removeFirst();
            }
        }

        private static class Command {
            Action action;
            byte[] diff;
            int offset;

            Command(Action action, byte[] diff, int offset) {
                this.action = action;
                this.diff = diff; // Making use of the original array, assuming that it's not used by any other functions
                this.offset = offset;
            }
        }
    }
}