package trust.nccgroup.decoderimproved;

import burp.IBurpExtenderCallbacks;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

class Logger {

    private static IBurpExtenderCallbacks callbacks = null;

    public static void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks){
        callbacks = _callbacks;
    }

    public static void printOutput(String outputString){
        if (callbacks != null) {
            callbacks.printOutput("[" + getCurrentDateString() + "] " + outputString);
        }
    }

    public static void printError(String errorString){
        if (callbacks != null) {
            callbacks.printError("[" + getCurrentDateString() + "] " + errorString);
        }
    }

    public static void printErrorFromException(Exception e) {
        if (callbacks != null) {
            try {
                StringWriter stringWriter = new StringWriter();
                PrintWriter printWriter = new PrintWriter(stringWriter);
                e.printStackTrace(printWriter);
                callbacks.printError(stringWriter.toString());
                printWriter.close();
                stringWriter.close();
            } catch (IOException ee){
                printError(ee.getMessage());
            }
        }
    }

    private static String getCurrentDateString() {
        LocalDateTime ldt = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm:ss");
        return dtf.format(ldt);
    }
}
