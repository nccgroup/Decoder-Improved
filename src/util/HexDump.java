package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class HexDump {

  public static void dump(byte[] arr) {
    try {
      for (int index = 0; index < arr.length; index += 16) {
        printHex(arr, index, 16);
        printAscii(arr, index, 16);
      }
    } catch (Throwable t) {
      t.printStackTrace();
    }
  }

  private static byte[] read(String inputFileName, int start, int end)
      throws FileNotFoundException, IOException {
    File theFile = new File(inputFileName);
    FileInputStream input = new FileInputStream(theFile);
    int skipped = 0;
    while (skipped < start) {
      skipped += input.skip(start - skipped);
    }
    int length = (int) (Math.min(end, theFile.length()) - start);
    byte[] bytes = new byte[length];
    int bytesRead = 0;
    while (bytesRead < bytes.length) {
      bytesRead = input.read(bytes, bytesRead, bytes.length - bytesRead);
      if (bytesRead == -1) {
        break;
      }
    }
    return bytes;
  }

  private static void printHex(byte[] bytes, int offset, int width) {
    for (int index = 0; index < width; index++) {
      if (index + offset < bytes.length) {
        System.out.printf("%02x ", bytes[index + offset]);
      } else {
        System.out.print("  ");
      }
    }
  }

  private static void printAscii(byte[] bytes, int index, int width)
      throws UnsupportedEncodingException {
    if (index < bytes.length) {
      width = Math.min(width, bytes.length - index);
      System.out.println(
          ":"
              + new String(bytes, index, width, StandardCharsets.UTF_8).replaceAll("\r\n", " ").replaceAll(
              "\n",
              " "));
    } else {
      System.out.println();
    }
  }
}