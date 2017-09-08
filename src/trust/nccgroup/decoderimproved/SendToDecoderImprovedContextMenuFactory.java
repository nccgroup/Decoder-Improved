package trust.nccgroup.decoderimproved;

import burp.*;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by j on 12/9/16.
 */
class SendToDecoderImprovedContextMenuFactory implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MultiDecoderTab tab;

    public SendToDecoderImprovedContextMenuFactory(IBurpExtenderCallbacks _callbacks, MultiDecoderTab _tab) {
        callbacks = _callbacks;
        helpers = callbacks.getHelpers();
        tab = _tab;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu = new ArrayList<>();
        byte ctx = invocation.getInvocationContext();
        ActionListener listener;

        if (ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
            listener = event -> {
                int start = invocation.getSelectionBounds()[0];
                int end = invocation.getSelectionBounds()[1];
                //tab.receiveTextFromMenu(new String(requestResponses[0].getRequest(), "UTF-8").substring(start, end));
                if (start == end) {
                    tab.receiveTextFromMenu(UTF8StringEncoder.newUTF8String(requestResponses[0].getRequest()));
                } else {
                    tab.receiveTextFromMenu(UTF8StringEncoder.newUTF8String(requestResponses[0].getRequest()).substring(start, end));
                }
            };
            //System.out.println("1");
        } else if (ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
            listener = event -> {
                int start = invocation.getSelectionBounds()[0];
                int end = invocation.getSelectionBounds()[1];
                if (start == end) {
                    tab.receiveTextFromMenu(UTF8StringEncoder.newUTF8String(requestResponses[0].getResponse()));
                } else {
                    tab.receiveTextFromMenu(UTF8StringEncoder.newUTF8String(requestResponses[0].getResponse()).substring(start, end));
                }
            };
            //System.out.println("1");
        } else {
            listener = e -> { };
        }

        JMenuItem item = new JMenuItem("Send to Decoder Improved", null);
        item.addActionListener(listener);
        menu.add(item);
        return menu;
    }
}
