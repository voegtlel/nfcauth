package de.infornautik.nfcauth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class DiscoveryProofTest {
    @Test
    fun signatureBindsTheFreshSessionAndService() {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val proof = DiscoveryProof.payload("service", "ab".repeat(32), "cd".repeat(32), "ef".repeat(32))
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(pair.private)
            update(proof)
            sign()
        }
        assertTrue(DiscoveryProof.verify(pair.public, proof, signature))
        for (changed in listOf(
            DiscoveryProof.payload("other", "ab".repeat(32), "cd".repeat(32), "ef".repeat(32)),
            DiscoveryProof.payload("service", "00".repeat(32), "cd".repeat(32), "ef".repeat(32)),
            DiscoveryProof.payload("service", "ab".repeat(32), "00".repeat(32), "ef".repeat(32)),
            DiscoveryProof.payload("service", "ab".repeat(32), "cd".repeat(32), "00".repeat(32)),
        )) assertFalse(DiscoveryProof.verify(pair.public, changed, signature))
    }

    @Test
    fun unknownOrChangedServiceCannotDiscoverTheUser() {
        val manifest = ServiceManifest(
            "service", "Service", "Operator", "https://example.test/privacy", "1",
            listOf("service_user_id", "authentication_public_key"),
            mapOf("service_user_id" to "Identify", "authentication_public_key" to "Verify"),
            "privacy@example.test", "public-key", "ab".repeat(16), false,
        )
        val verified = VerifiedServiceManifest(manifest, false, "signing", "encryption", "hash")
        val registration = ReaderInfo(
            "service", "Service", "Operator", false, "opaque-user-id", null,
            "https://example.test/privacy", "1", manifest.requestedFields, manifest.purposes,
            "privacy@example.test", "encryption", "signing", "hash", 1000,
        )
        assertEquals("opaque-user-id", DiscoveryProof.requireApproved(registration, verified).userId)
        assertThrows(IllegalArgumentException::class.java) { DiscoveryProof.requireApproved(null, verified) }
        for (changed in listOf(
            verified.copy(signingKeyFingerprint = "different"),
            verified.copy(encryptionKeyFingerprint = "different"),
            verified.copy(manifest = manifest.copy(operatorName = "Someone else")),
            verified.copy(manifest = manifest.copy(privacyNoticeVersion = "2")),
            verified.copy(manifest = manifest.copy(serviceId = "different")),
            verified.copy(manifest = manifest.copy(requestedFields = listOf("alias"))),
        )) assertThrows(IllegalArgumentException::class.java) {
            DiscoveryProof.requireApproved(registration, changed)
        }
    }

    @Test
    fun bindingMatchesAtBothEndsAndIsDifferentForAnotherSession() {
        val initiator = NfcSessionCrypto.createInitiator()
        val phone = NfcSessionCrypto.accept(initiator.request)
        val reader = initiator.complete(phone.response)
        assertEquals(reader.discoveryBinding(), phone.session.discoveryBinding())
        assertEquals(64, reader.discoveryBinding().length)
        val other = NfcSessionCrypto.createInitiator()
        val otherPhone = NfcSessionCrypto.accept(other.request)
        assertFalse(reader.discoveryBinding() == otherPhone.session.discoveryBinding())
    }
}
