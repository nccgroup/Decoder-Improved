package trust.nccgroup.decoderimproved;

import burp.*;
import trust.nccgroup.decoderimproved.components.MultiDecoderTab;

import java.lang.reflect.Field;
import java.nio.charset.Charset;

public class ExtensionRoot implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public MultiDecoderTab multiDecoderTab;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {

        callbacks = _callbacks;
        helpers = callbacks.getHelpers();

        Logger.registerExtenderCallbacks(callbacks);

        callbacks.setExtensionName("Decoder Improved");

        // Set Java Default Character encoding type to UTF-8 (which might not be default on Windows)
        // This is required (at least) for HTML entity related actions
        try {
            if (!System.getProperty("file.encoding").equalsIgnoreCase("UTF-8")) {
                System.setProperty("file.encoding", "UTF-8");
                Field charset = Charset.class.getDeclaredField("defaultCharset");
                charset.setAccessible(true);
                charset.set(null, null);
                charset.setAccessible(false);
            }
        } catch (Exception e) {
            Logger.printErrorFromException(e);
        }

        multiDecoderTab = new MultiDecoderTab(this);
        //callbacks.customizeUiComponent(multiDecoderTab);
        callbacks.addSuiteTab(multiDecoderTab);
        callbacks.registerContextMenuFactory(new SendToDecoderImprovedContextMenuFactory(multiDecoderTab));

        String savedSettings = callbacks.loadExtensionSetting(multiDecoderTab.getTabCaption());
        // null state will be handled in MultiDecoderTab
        multiDecoderTab.setState(savedSettings, true);

        setSaveFullState();
    }

    public void setSaveFullState() {
        callbacks.getExtensionStateListeners().forEach((x) -> callbacks.removeExtensionStateListener(x));
        callbacks.registerExtensionStateListener(() -> callbacks.saveExtensionSetting(multiDecoderTab.getTabCaption(), multiDecoderTab.getState()));
    }

    public void setClearState() {
        callbacks.getExtensionStateListeners().forEach((x) -> callbacks.removeExtensionStateListener(x));
        callbacks.registerExtensionStateListener(() -> callbacks.saveExtensionSetting(multiDecoderTab.getTabCaption(), null));
    }
}
