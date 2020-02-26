package trust.nccgroup.decoderimproved.components;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;

// Originally from http://stackoverflow.com/questions/1377887/jtextpane-prevents-scrolling-in-the-parent-jscrollpane/1379695#1379695

/**
 * A JScrollPane that will bubble a mouse wheel scroll event to the parent
 * JScrollPane if one exists when this scrollpane either tops out or bottoms out.
 */
class PDControlScrollPane extends JScrollPane {

    PDControlScrollPane() {
        super();

        addMouseWheelListener(new PDMouseWheelListener());
    }

    class PDMouseWheelListener implements MouseWheelListener {

        private JScrollBar horizontalBar;
        private JScrollBar verticalBar;
        private int horizontalPreviousValue = 0;
        private int verticalPreviousValue = 0;
        private JScrollPane parentScrollPane;

        private JScrollPane getParentScrollPane() {
            if (parentScrollPane == null) {
                Component parent = getParent();
                while (!(parent instanceof JScrollPane) && parent != null) {
                    parent = parent.getParent();
                }
                parentScrollPane = (JScrollPane) parent;
            }
            return parentScrollPane;
        }

        PDMouseWheelListener() {
            horizontalBar = PDControlScrollPane.this.getHorizontalScrollBar();
            verticalBar = PDControlScrollPane.this.getVerticalScrollBar();
        }

        @Override
        public void mouseWheelMoved(MouseWheelEvent e) {
            JScrollPane parent = getParentScrollPane();
            if (parent != null) {
                /*
                 * Only dispatch if we have reached top/bottom on previous scroll
                 */
                if (e.getWheelRotation() < 0) {
                    // If vertical scroll bar exists
                    if (getMax(verticalBar) > 0) {
                        if (verticalBar.getValue() == 0 && verticalPreviousValue == 0) {
                            parent.dispatchEvent(cloneEvent(e));
                        }
                    } else if (horizontalBar.getValue() == 0 && horizontalPreviousValue == 0) {
                        parent.dispatchEvent(cloneEvent(e));
                    }

                } else {
                    // If vertical scroll bar exists
                    if (getMax(verticalBar) > 0) {
                        if (verticalBar.getValue() == getMax(verticalBar) && verticalPreviousValue == getMax(verticalBar)) {
                            parent.dispatchEvent(cloneEvent(e));
                        }
                    } else if (horizontalBar.getValue() == getMax(horizontalBar) && horizontalPreviousValue == getMax(horizontalBar)) {
                        parent.dispatchEvent(cloneEvent(e));
                    }
                }
                horizontalPreviousValue = horizontalBar.getValue();
                verticalPreviousValue = verticalBar.getValue();
            }
            /*
             * If parent scrollpane doesn't exist, remove this as a listener.
             * We have to defer this till now (vs doing it in constructor)
             * because in the constructor this item has no parent yet.
             */
            else {
                PDControlScrollPane.this.removeMouseWheelListener(this);
            }
        }

        private int getMax(JScrollBar bar) {
            return bar.getMaximum() - bar.getVisibleAmount();
        }

        private MouseWheelEvent cloneEvent(MouseWheelEvent e) {
            return new MouseWheelEvent(getParentScrollPane(), e.getID(), e
                    .getWhen(), e.getModifiersEx(), 1, 1, e
                    .getClickCount(), false, e.getScrollType(), e
                    .getScrollAmount(), e.getWheelRotation());
        }
    }
}
