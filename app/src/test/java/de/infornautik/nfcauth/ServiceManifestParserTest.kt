package de.infornautik.nfcauth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ServiceManifestParserTest {
    @Test
    fun acceptsHttpsAndEmailDeletionDestinations() {
        listOf(
            "https://example.com/account/delete",
            "privacy@example.com",
            "mailto:privacy@example.com",
        ).forEach { value ->
            assertEquals(value, ServiceManifestParser.validateDeletionUrlOrContact(value))
        }
    }

    @Test
    fun rejectsUnsafeDeletionDestinations() {
        listOf(
            "http://example.com/account/delete",
            "intent://account/delete",
            "javascript:alert(1)",
            " privacy@example.com",
            "mailto:privacy@example.com?subject=delete",
        ).forEach { value ->
            assertThrows(IllegalArgumentException::class.java) {
                ServiceManifestParser.validateDeletionUrlOrContact(value)
            }
        }
    }
}
