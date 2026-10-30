package de.infornautik.nfcauth

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NfcSessionCryptoTest {
    @Test
    fun provisionalSessionOnlyCarriesCertificateProofThenRekeys() {
        val sessionId = ByteArray(16) { it.toByte() }
        val secret = ByteArray(32) { (it + 1).toByte() }
        val reader = NfcSessionCrypto.fromSharedSecretForTest(sessionId, secret, true)
        val phone = NfcSessionCrypto.fromSharedSecretForTest(sessionId, secret, false)
        assertThrows(IllegalArgumentException::class.java) {
            reader.encrypt("secret".toByteArray(), "registration")
        }
        val proof = reader.encrypt(
            "certificate".toByteArray(),
            NfcSessionCrypto.PURPOSE_SESSION_AUTHENTICATION,
        )
        assertArrayEquals(
            "certificate".toByteArray(),
            phone.decrypt(proof, NfcSessionCrypto.PURPOSE_SESSION_AUTHENTICATION),
        )
        val transcript = ByteArray(32) { 7 }
        reader.authenticate(transcript)
        phone.authenticate(transcript)
        val encrypted = reader.encrypt("secret".toByteArray(), "registration")
        assertArrayEquals("secret".toByteArray(), phone.decrypt(encrypted, "registration"))
        assertThrows(Exception::class.java) { phone.decrypt(encrypted, "registration") }
    }

    @Test
    fun providerOriginIsCanonicalizedBeforeItNamespacesCredentials() {
        assertEquals(
            "https://auth.example.com",
            ServiceManifestParser.canonicalOrigin("HTTPS://AUTH.EXAMPLE.COM:443/"),
        )
        assertEquals(
            "https://auth.example.com:8443",
            ServiceManifestParser.canonicalOrigin("https://AUTH.EXAMPLE.COM:8443"),
        )
    }
}
