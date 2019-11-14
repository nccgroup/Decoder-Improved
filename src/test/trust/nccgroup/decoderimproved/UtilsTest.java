package trust.nccgroup.decoderimproved;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    private static byte[][] validUTF8CharProvider() {
        return new byte[][] {
                new byte[] {(byte)0b00000000},
                new byte[] {(byte)0b00101010},
                new byte[] {(byte)0b01111111},
                new byte[] {(byte)0b11000000, (byte)0b10000000},
                new byte[] {(byte)0b11011111, (byte)0b10111111},
                new byte[] {(byte)0b11100000, (byte)0b10111111, (byte)0b10000000},
                new byte[] {(byte)0b11101111, (byte)0b10111111, (byte)0b10111111},
                new byte[] {(byte)0b11110000, (byte)0b10000000, (byte)0b10000000, (byte)0b10000000},
                new byte[] {(byte)0b11110111, (byte)0b10111111, (byte)0b10111111, (byte)0b10111111},
        };
    }

    private static byte[][] invalidUTF8CharProvider() {
        return new byte[][] {
                new byte[] {(byte)0b10000000},
                new byte[] {(byte)0b10100000},
                new byte[] {(byte)0b11111000},
                new byte[] {(byte)0b11111111},
                new byte[] {(byte)0b11000000},
                new byte[] {(byte)0b11000000, (byte)0b10000000, (byte)0b10000000},
                new byte[] {(byte)0b11000000, (byte)0b10000000, (byte)0b10000000, (byte)0b10000000},
                new byte[] {(byte)0b11110111, (byte)0b10000000, (byte)0b10000000, (byte)0b10000000, (byte)0b10000000},
        };
    }

    @ParameterizedTest
    @MethodSource("validUTF8CharProvider")
    void testIsUTF8Char(byte[] input) {
        assertTrue(Utils.isUTF8Char(input));
    }

    @ParameterizedTest
    @MethodSource("invalidUTF8CharProvider")
    void testIsUTF8CharReturnFalse(byte[] input) {
        assertFalse(Utils.isUTF8Char(input));
    }
}