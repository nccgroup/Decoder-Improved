package trust.nccgroup.decoderimproved;

import burp.IBurpExtenderCallbacks;

public class Logger {
    private static IBurpExtenderCallbacks callbacks = null;

    public static void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks){
        callbacks = _callbacks;
    }

    public static void printOutput(String outputString){
        if (callbacks != null) {
            callbacks.printOutput(outputString);
        }
    }

    public static void printError(String errorString){
        if (callbacks != null) {
            callbacks.printError(errorString);
        }
    }
}
