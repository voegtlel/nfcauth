package de.infornautik.nfcauth

import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class BoundedHttpTest {
    @Test
    fun acceptsExactLimitAndRejectsExcess() {
        assertEquals("test", BoundedHttp.readJson(ByteArrayInputStream("test".toByteArray()), 4))
        assertThrows(IllegalArgumentException::class.java) {
            BoundedHttp.readJson(ByteArrayInputStream(ByteArray(65537)), 65536)
        }
    }

    @Test
    fun limitsBytesBeforeUtf8Decoding() {
        assertThrows(IllegalArgumentException::class.java) {
            BoundedHttp.readJson(ByteArrayInputStream("éé".toByteArray(Charsets.UTF_8)), 3)
        }
    }
}
