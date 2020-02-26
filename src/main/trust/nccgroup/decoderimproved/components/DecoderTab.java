package trust.nccgroup.decoderimproved.components;

import trust.nccgroup.decoderimproved.ModificationException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class DecoderTab extends JPanel {
    MainTab mainTab;
    DecoderTabHandle decoderTabHandle;
    JPanel decoderTabBody;
    ArrayList<DecoderSegment> decoderSegments;

    private JScrollPane scrollingBodyHolder;

    DecoderTab(String _title, MainTab _parent) {
        mainTab = _parent;
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

    void addDecoderSegment() {
        DecoderSegment ds = new DecoderSegment(this);
        //decoderTabBody.add(Box.createRigidArea(new Dimension(0, 10)));
        decoderSegments.add(ds);
        decoderTabBody.add(ds);

        // Update last segment (based on second last segment)
        updateNextDecoderSegment(decoderSegments.size() - 2);
    }

    void removeDecoderSegment(DecoderSegment decoderSegment) {
        decoderTabBody.remove(decoderSegment);
        decoderSegments.remove(decoderSegment);
        if (decoderSegments.size() == 0) {
            addDecoderSegment();
        }
        mainTab.repaint();
        updateDecoderSegments(0, false);
        decoderSegment.dsState.clear();
    }

    void updateDecoderSegments(int activeDecoderSegmentIndex, boolean addSegment) {
        if (addSegment && activeDecoderSegmentIndex == decoderSegments.size() - 1) {
            addDecoderSegment();
        }
        // This goes through the entire list of decoder segments and updates all the ones
        // past the current one.
        for (int i = activeDecoderSegmentIndex; i < decoderSegments.size(); i++) {
            updateNextDecoderSegment(i);
            int byteSize = decoderSegments.get(i).dsState.getByteSize();
            if (byteSize <= 1000000) {
                decoderSegments.get(i).setTextInfo(byteSize + " Bytes");
            } else if (byteSize <= 1000000000) {
                decoderSegments.get(i).setTextInfo(byteSize / 1000 + " KB");
            } else {
                decoderSegments.get(i).setTextInfo(byteSize / 1000000 + " MB");
            }
        }
    }

    private void updateNextDecoderSegment(int activeDecoderSegmentIndex) {
        // If the item is at the end of the list there isn't anything to update
        // i.e. this prevents an array out of bounds error
        if (activeDecoderSegmentIndex < 0 || activeDecoderSegmentIndex >= decoderSegments.size() - 1) {
            return;
        }

        // Get the active segment
        DecoderSegment activeDecoderSegment = decoderSegments.get(activeDecoderSegmentIndex);

        // This gets the next decoder segment
        DecoderSegment nextDecoderSegment = decoderSegments.get(activeDecoderSegmentIndex + 1);

        // Check to see if there was an error in the active decoder segment
        // If there was an error in a previous decoder segment propagate that to all following segments
        // Then change the text editor background red and display the error message
        if (activeDecoderSegment.hasError) {
            nextDecoderSegment.hasError = true;
            nextDecoderSegment.showError(activeDecoderSegment.errorMessage);
            return;
        }

        //This code does all the byte modification
        try {
            nextDecoderSegment.dsState.setByteArrayList(activeDecoderSegment.modeManager.modifyBytes(activeDecoderSegment.dsState.getByteArray()));
            nextDecoderSegment.updateEditors(nextDecoderSegment.dsState);
            nextDecoderSegment.hasError = false;
            try {
                CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
                decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
                decoder.onMalformedInput(CodingErrorAction.REPORT);
                decoder.decode(ByteBuffer.wrap(nextDecoderSegment.dsState.getByteArray()));
                // new String(nextDecoderSegment.dsState.getByteArray(), StandardCharsets.UTF_8);
                // new UTF.newUTF8String(nextDecoderSegment.dsState.getByteArray());
                nextDecoderSegment.displayTextEditor();
            } catch (Exception e) {
                nextDecoderSegment.displayHexEditor();
            }
        } catch (ModificationException e) {
            nextDecoderSegment.showError(e.getMessage());
        }
    }

    static class DecoderTabHandle extends JPanel {
        private JTabbedPane parentTabbedPane;
        DecoderTab decoderTab;
        JTextField tabNameField;
        JButton closeButton;

        private DecoderTabHandle(String title, MainTab mainTab, DecoderTab decoderTab) {
            this.decoderTab = decoderTab;
            this.parentTabbedPane = mainTab.getTabbedPane();
            this.setLayout(new FlowLayout(FlowLayout.LEFT, 0, 0));
            this.setOpaque(false);
            JLabel label = new JLabel(title);
            label.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
            tabNameField = new JTextField(title);
            tabNameField.setOpaque(false);
            tabNameField.setBorder(null);
            tabNameField.setBackground(new Color(0, 0, 0, 0));
            tabNameField.setEditable(false);
            tabNameField.setCaretColor(Color.BLACK);

            this.add(tabNameField);
            closeButton = new JButton("✕");
            closeButton.setFont(new Font("monospaced", Font.PLAIN, 10));
            closeButton.setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 2));
            closeButton.setForeground(Color.GRAY);

            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);
            closeButton.setOpaque(false);

            tabNameField.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    parentTabbedPane.setSelectedComponent(decoderTab);
                    if (SwingUtilities.isRightMouseButton(e)) {
                        parentTabbedPane.dispatchEvent(e);
                    } else if (SwingUtilities.isMiddleMouseButton(e)) {
                        mainTab.closeTab(decoderTab);
                    } else if (e.getClickCount() >= 2) {
                        tabNameField.setEditable(true);
                    }
                }
            });

            tabNameField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    tabNameField.setEditable(false);
                    // Add a single space to an empty name to keep it selectable for editing
                    if (tabNameField.getText().isEmpty()) {
                        tabNameField.setText(" ");
                    }
                    super.focusLost(e);
                }
            });

            //closeButton.addActionListener(e -> mainTab.closeTab(decoderTab));
            closeButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        parentTabbedPane.setSelectedComponent(decoderTab);
                        parentTabbedPane.dispatchEvent(e);
                    } else {
                        mainTab.closeTab(decoderTab);
                    }
                }
            });

            this.add(closeButton);
        }
    }
}
