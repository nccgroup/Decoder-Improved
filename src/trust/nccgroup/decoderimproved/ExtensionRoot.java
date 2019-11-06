package trust.nccgroup.decoderimproved;

import burp.*;
import trust.nccgroup.decoderimproved.components.MainTab;

import java.lang.reflect.Field;
import java.nio.charset.Charset;

public class ExtensionRoot {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public MainTab mainTab;

    public ExtensionRoot(IBurpExtenderCallbacks _callbacks) {

        callbacks = _callbacks;
        helpers = callbacks.getHelpers();

        Logger.loadExtenderCallbacks(callbacks);

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

        mainTab = new MainTab(this);
        //callbacks.customizeUiComponent(mainTab);
        callbacks.addSuiteTab(mainTab);
        callbacks.registerContextMenuFactory(new SendToDecoderImprovedContextMenuFactory(mainTab));

        String savedSettings = callbacks.loadExtensionSetting(mainTab.getTabCaption());
        // null state will be handled in MainTab
        mainTab.setState(savedSettings, true);

        setSaveFullState();
    }

    public void setSaveFullState() {
        callbacks.getExtensionStateListeners().forEach((x) -> callbacks.removeExtensionStateListener(x));
        callbacks.registerExtensionStateListener(() -> callbacks.saveExtensionSetting(mainTab.getTabCaption(), mainTab.getState()));
    }

    public void setClearState() {
        callbacks.getExtensionStateListeners().forEach((x) -> callbacks.removeExtensionStateListener(x));
        callbacks.registerExtensionStateListener(() -> callbacks.saveExtensionSetting(mainTab.getTabCaption(), null));
    }
}
