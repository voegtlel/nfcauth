package de.infornautik.nfcauth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RegistrationLinkTest {
    @Test
    fun acceptsBothLinkFormsAndNormalizesOrigin() {
        listOf("nfcauth://register", "https://voegtlel.github.io/nfcauth/register.html").forEach {
            assertEquals("https://auth.example.com", RegistrationLink.providerOrigin(
                "$it?provider=https%3A%2F%2FAUTH.example.com%3A443%2F",
            ))
        }
    }

    @Test
    fun rejectsAmbiguousOrUnsafeLinks() {
        listOf(
            "nfcauth://register", "nfcauth://registration-complete?provider=https://example.com",
            "nfcauth://register?provider=http://example.com",
            "nfcauth://register?provider=https://user@example.com",
            "nfcauth://register?provider=https://example.com/path",
            "nfcauth://register?provider=https://example.com&provider=https://other.example",
            "nfcauth://register?provider=https://example.com&token=secret",
            "nfcauth://register?provider=https://example.com#fragment",
            "nfcauth://user@register?provider=https://example.com",
            "https://evil.example/nfcauth/register.html?provider=https://example.com",
            "nfcauth://register?provider=%ZZ",
        ).forEach { link ->
            assertThrows(Exception::class.java) { RegistrationLink.providerOrigin(link) }
        }
    }
}
