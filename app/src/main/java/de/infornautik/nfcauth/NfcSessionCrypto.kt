package de.infornautik.nfcauth

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class NfcSessionContext(
    val sessionId: ByteArray,
    val phoneChallenge: ByteArray,
    val readerEphemeralPublicKey: ByteArray,
    val phoneEphemeralPublicKey: ByteArray,
)

class NfcSessionCrypto private constructor(
    private val sessionId: ByteArray,
    private var rootKey: ByteArray,
    private val sendDirection: Byte,
    private val receiveDirection: Byte,
) {
    data class AcceptedSession(
        val session: NfcSessionCrypto,
        val response: ByteArray,
        val context: NfcSessionContext,
    )

    private var transportKey = ByteArray(0)
    private var bindingKey = ByteArray(0)
    private var sendCounter = 0uL
    private var receiveCounter = 0uL
    private var authenticated = false
    private var terminated = false
    private val random = SecureRandom()

    init {
        deriveSubkeys()
    }

    @Synchronized
    fun authenticate(transcriptHash: ByteArray) {
        require(!authenticated && transcriptHash.size == 32) { "Invalid session authentication state" }
        val updated = hkdf(rootKey, sessionId, AUTHENTICATED_INFO + transcriptHash)
        rootKey.fill(0)
        rootKey = updated
        deriveSubkeys()
        sendCounter = 0uL
        receiveCounter = 0uL
        authenticated = true
    }

    fun discoveryBinding(): String {
        require(authenticated) { "Service identity is not authenticated" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(bindingKey, "HmacSHA256"))
        return mac.doFinal("nfcauth-v3-credential-discovery-binding".toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray, purpose: String): ByteArray {
        requirePurpose(purpose)
        require(!terminated) { "Encrypted NFC session is terminated" }
        if (sendCounter == ULong.MAX_VALUE) {
            terminated = true
            error("Encrypted NFC send sequence exhausted")
        }
        val sequence = encodeSequence(sendCounter)
        val iv = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(transportKey, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad(sendDirection, purpose, sequence))
        val result = byteArrayOf(VERSION.toByte()) + sessionId + sequence + iv + cipher.doFinal(plaintext)
        sendCounter += 1u
        return result
    }

    @Synchronized
    fun decrypt(envelope: ByteArray, purpose: String): ByteArray {
        requirePurpose(purpose)
        require(!terminated && envelope.size >= 53 && envelope[0].toInt() and 0xff == VERSION)
        require(MessageDigest.isEqual(sessionId, envelope.copyOfRange(1, 17)))
        val sequence = envelope.copyOfRange(17, 25)
        require(decodeSequence(sequence) == receiveCounter) { "Unexpected encrypted NFC sequence" }
        val iv = envelope.copyOfRange(25, 37)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(transportKey, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad(receiveDirection, purpose, sequence))
        val result = cipher.doFinal(envelope.copyOfRange(37, envelope.size))
        receiveCounter += 1u
        return result
    }

    private fun requirePurpose(purpose: String) {
        require(purpose.isNotBlank())
        require(authenticated || purpose == PURPOSE_SESSION_AUTHENTICATION) {
            "Service identity must be authenticated first"
        }
    }

    private fun deriveSubkeys() {
        transportKey.fill(0)
        bindingKey.fill(0)
        transportKey = hkdf(rootKey, sessionId, "nfcauth-v3-transport".toByteArray())
        bindingKey = hkdf(rootKey, sessionId, "nfcauth-v3-binding".toByteArray())
    }

    private fun aad(direction: Byte, purpose: String, sequence: ByteArray): ByteArray {
        val purposeBytes = purpose.toByteArray(StandardCharsets.UTF_8)
        return ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use {
                it.writeByte(VERSION)
                it.write(sessionId)
                it.writeByte(direction.toInt())
                it.writeShort(purposeBytes.size)
                it.write(purposeBytes)
                it.write(sequence)
            }
        }.toByteArray()
    }

    companion object {
        const val VERSION = 3
        const val SESSION_ID_LENGTH = 16
        const val PUBLIC_KEY_LENGTH = 65
        const val PHONE_CHALLENGE_LENGTH = 32
        const val PURPOSE_SESSION_AUTHENTICATION = "session-authentication"
        private val PROVISIONAL_INFO = "nfcauth-v3-provisional-session".toByteArray()
        private val AUTHENTICATED_INFO = "nfcauth-v3-authenticated-session".toByteArray()

        fun accept(request: ByteArray): AcceptedSession {
            require(request.size == 82 && request[0].toInt() and 0xff == VERSION)
            val sessionId = request.copyOfRange(1, 17)
            val readerPublic = request.copyOfRange(17, 82)
            val phoneKey = generateKeyPair()
            val phonePublic = encodePublicKey(phoneKey)
            val challenge = ByteArray(PHONE_CHALLENGE_LENGTH).also(SecureRandom()::nextBytes)
            val session = deriveSession(sessionId, phoneKey, readerPublic)
            return AcceptedSession(
                session,
                byteArrayOf(VERSION.toByte()) + sessionId + phonePublic + challenge,
                NfcSessionContext(sessionId, challenge, readerPublic, phonePublic),
            )
        }

        internal fun fromSharedSecretForTest(
            sessionId: ByteArray,
            sharedSecret: ByteArray,
            isInitiator: Boolean = true,
        ): NfcSessionCrypto {
            val root = hkdf(sharedSecret, sessionId, PROVISIONAL_INFO)
            return NfcSessionCrypto(
                sessionId.copyOf(),
                root,
                if (isInitiator) 0 else 1,
                if (isInitiator) 1 else 0,
            )
        }

        private fun deriveSession(sessionId: ByteArray, own: KeyPair, peerEncoded: ByteArray): NfcSessionCrypto {
            val ownPublic = own.public as ECPublicKey
            val point = ECPoint(
                BigInteger(1, peerEncoded.copyOfRange(1, 33)),
                BigInteger(1, peerEncoded.copyOfRange(33, 65)),
            )
            require(peerEncoded.size == 65 && peerEncoded[0] == 4.toByte())
            val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, ownPublic.params))
            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(own.private)
            agreement.doPhase(peer, true)
            val shared = agreement.generateSecret()
            val root = hkdf(shared, sessionId, PROVISIONAL_INFO)
            shared.fill(0)
            return NfcSessionCrypto(sessionId, root, 1, 0)
        }

        private fun generateKeyPair() = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            generateKeyPair()
        }

        private fun encodePublicKey(pair: KeyPair): ByteArray {
            val key = pair.public as ECPublicKey
            return byteArrayOf(4) + fixed(key.w.affineX) + fixed(key.w.affineY)
        }

        private fun fixed(value: BigInteger): ByteArray {
            val raw = value.toByteArray()
            val unsigned = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
            return ByteArray(32).also { unsigned.copyInto(it, 32 - unsigned.size) }
        }

        private fun encodeSequence(value: ULong) =
            ByteArray(8) { index -> (value shr ((7 - index) * 8)).toByte() }

        private fun decodeSequence(value: ByteArray) =
            value.fold(0uL) { result, byte -> (result shl 8) or byte.toUByte().toULong() }

        internal fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
            val extract = Mac.getInstance("HmacSHA256")
            extract.init(SecretKeySpec(salt, "HmacSHA256"))
            val prk = extract.doFinal(ikm)
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(info)
            expand.update(1)
            return expand.doFinal().also { prk.fill(0) }
        }
    }
}
