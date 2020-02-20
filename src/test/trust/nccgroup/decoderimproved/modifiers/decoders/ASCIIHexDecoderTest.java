package trust.nccgroup.decoderimproved.modifiers.decoders;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import trust.nccgroup.decoderimproved.ModificationException;

import static org.junit.jupiter.api.Assertions.*;

class ASCIIHexDecoderTest {
    private ASCIIHexDecoder asciiHexDecoder;

    @BeforeEach
    void setUp() {
        asciiHexDecoder = new ASCIIHexDecoder();
    }

    @AfterEach
    void tearDown() {
        asciiHexDecoder = null;
    }

    @Test
    void testModifyBytes() throws ModificationException {
        final byte[] input = {(byte)0x38, (byte)0x62, (byte)0x42, (byte)0x32, (byte)0x45, (byte)0x66};
        final byte[] expected = {(byte)0x8b, (byte)0xb2, (byte)0xef};
        assertArrayEquals(expected, asciiHexDecoder.modifyBytes(input));
    }

    @ParameterizedTest
    @ValueSource(bytes = {(byte) 0x00, (byte) 0x10, (byte) 0x2f, (byte) 0x47, (byte) 0x67, (byte) 0xef})
    void testModifyBytesThrowsModificationException(byte badByte) {
        final byte[] input1 = {(byte) 0x32, badByte};
        final byte[] input2 = {badByte, (byte) 0x32};
        assertThrows(ModificationException.class, () -> {
            asciiHexDecoder.modifyBytes(input1);
            asciiHexDecoder.modifyBytes(input2);
        });
    }
}