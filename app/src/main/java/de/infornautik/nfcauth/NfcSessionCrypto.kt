package de.infornautik.nfcauth

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

/**
 * Version 2 NFC transport encryption.
 *
 * Each NFC presentation starts with an ephemeral P-256 ECDH handshake. The
 * resulting secret is expanded with HKDF-SHA-256 and used only for this NFC
 * session with AES-256-GCM. Handshake public keys and random session IDs are
 * not confidential; every application payload is encrypted and authenticated.
 */
class NfcSessionCrypto private constructor(
    private val sessionId: ByteArray,
    keyBytes: ByteArray,
    private val sendDirection: Byte,
    private val receiveDirection: Byte,
    sendCounter: ULong = 0uL,
    receiveCounter: ULong = 0uL,
) {
    data class AcceptedSession(
        val session: NfcSessionCrypto,
        val response: ByteArray,
    )

    class Initiator internal constructor(
        private val sessionId: ByteArray,
        private val keyPair: KeyPair,
    ) {
        val request: ByteArray = encodeHandshake(sessionId, encodePublicKey(keyPair))

        fun complete(response: ByteArray): NfcSessionCrypto {
            val parsed = parseHandshake(response)
            require(MessageDigest.isEqual(sessionId, parsed.sessionId)) {
                "NFC session ID mismatch"
            }
            return deriveSession(sessionId, keyPair, parsed.publicKey, isInitiator = true)
        }
    }

    private val key = SecretKeySpec(keyBytes.copyOf(), AES_ALGORITHM)
    private val random = SecureRandom()
    private var sendCounter = sendCounter
    private var receiveCounter = receiveCounter
    private var terminated = false

    @Synchronized
    fun encrypt(plaintext: ByteArray, purpose: String): ByteArray {
        require(!terminated) { "Encrypted NFC session is terminated" }
        if (sendCounter == ULong.MAX_VALUE) {
            terminated = true
            throw IllegalArgumentException("Encrypted NFC send sequence exhausted")
        }
        val sequence = sendCounter
        val encodedSequence = encodeSequence(sequence)
        val iv = ByteArray(GCM_IV_LENGTH).also(random::nextBytes)
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(authenticatedData(sendDirection, purpose, encodedSequence))
        val ciphertext = cipher.doFinal(plaintext)

        val envelope =
            byteArrayOf(VERSION.toByte()) + sessionId + encodedSequence + iv + ciphertext
        sendCounter = sequence + 1uL
        return envelope
    }

    @Synchronized
    fun decrypt(envelope: ByteArray, purpose: String): ByteArray {
        require(!terminated) { "Encrypted NFC session is terminated" }
        require(envelope.size >= ENVELOPE_OVERHEAD + GCM_TAG_LENGTH) {
            "Encrypted NFC payload is too short"
        }
        require(envelope[0].toUByte().toInt() == VERSION) {
            "Unsupported encrypted NFC payload version"
        }

        val envelopeSessionId = envelope.copyOfRange(1, 1 + SESSION_ID_LENGTH)
        require(MessageDigest.isEqual(sessionId, envelopeSessionId)) {
            "Encrypted NFC payload belongs to another session"
        }

        if (receiveCounter == ULong.MAX_VALUE) {
            terminated = true
            throw IllegalArgumentException("Encrypted NFC receive sequence exhausted")
        }
        val sequenceStart = 1 + SESSION_ID_LENGTH
        val ivStart = sequenceStart + SEQUENCE_LENGTH
        val encodedSequence = envelope.copyOfRange(sequenceStart, ivStart)
        val sequence = decodeSequence(encodedSequence)
        require(sequence == receiveCounter) {
            "Unexpected encrypted NFC sequence: expected $receiveCounter, received $sequence"
        }

        val ciphertextStart = ivStart + GCM_IV_LENGTH
        val iv = envelope.copyOfRange(ivStart, ciphertextStart)
        val ciphertext = envelope.copyOfRange(ciphertextStart, envelope.size)

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(authenticatedData(receiveDirection, purpose, encodedSequence))
        val plaintext = cipher.doFinal(ciphertext)
        receiveCounter += 1uL
        return plaintext
    }

    private fun authenticatedData(
        direction: Byte,
        purpose: String,
        encodedSequence: ByteArray,
    ): ByteArray {
        require(purpose.isNotBlank()) { "NFC encryption purpose must not be blank" }
        require(encodedSequence.size == SEQUENCE_LENGTH)
        return byteArrayOf(VERSION.toByte()) +
            sessionId +
            byteArrayOf(direction) +
            purpose.toByteArray(StandardCharsets.UTF_8) +
            encodedSequence
    }

    companion object {
        const val VERSION = 2
        const val SESSION_ID_LENGTH = 16
        const val PUBLIC_KEY_LENGTH = 65
        const val SEQUENCE_LENGTH = 8
        const val DIRECTION_READER_TO_PHONE = 0
        const val DIRECTION_PHONE_TO_READER = 1

        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16
        private const val GCM_TAG_BITS = GCM_TAG_LENGTH * 8
        private const val ENVELOPE_OVERHEAD =
            1 + SESSION_ID_LENGTH + SEQUENCE_LENGTH + GCM_IV_LENGTH
        private const val AES_ALGORITHM = "AES"
        private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val HKDF_ALGORITHM = "HmacSHA256"
        private const val CURVE_NAME = "secp256r1"
        private val HKDF_INFO = "nfcauth-nfc-session-v2".toByteArray(StandardCharsets.UTF_8)

        fun createInitiator(): Initiator {
            val sessionId = ByteArray(SESSION_ID_LENGTH).also(SecureRandom()::nextBytes)
            return Initiator(sessionId, generateKeyPair())
        }

        fun accept(request: ByteArray): AcceptedSession {
            val parsed = parseHandshake(request)
            val keyPair = generateKeyPair()
            val session = deriveSession(
                parsed.sessionId,
                keyPair,
                parsed.publicKey,
                isInitiator = false,
            )
            val response = encodeHandshake(parsed.sessionId, encodePublicKey(keyPair))
            return AcceptedSession(session, response)
        }

        internal fun fromSharedSecretForTest(
            sessionId: ByteArray,
            sharedSecret: ByteArray,
            isInitiator: Boolean = true,
            sendCounter: ULong = 0uL,
            receiveCounter: ULong = 0uL,
        ): NfcSessionCrypto {
            require(sessionId.size == SESSION_ID_LENGTH)
            val keyBytes = hkdfSha256(sharedSecret, sessionId, HKDF_INFO, 32)
            return createSession(
                sessionId,
                keyBytes,
                isInitiator,
                sendCounter,
                receiveCounter,
            ).also {
                keyBytes.fill(0)
            }
        }

        private data class ParsedHandshake(
            val sessionId: ByteArray,
            val publicKey: ByteArray,
        )

        private fun generateKeyPair(): KeyPair {
            return KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec(CURVE_NAME), SecureRandom())
                generateKeyPair()
            }
        }

        private fun deriveSession(
            sessionId: ByteArray,
            ownKeyPair: KeyPair,
            peerEncodedPublicKey: ByteArray,
            isInitiator: Boolean,
        ): NfcSessionCrypto {
            val ownPublicKey = ownKeyPair.public as ECPublicKey
            val peerPoint = decodePoint(peerEncodedPublicKey)
            val peerPublicKey = KeyFactory.getInstance("EC").generatePublic(
                ECPublicKeySpec(peerPoint, ownPublicKey.params),
            )

            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(ownKeyPair.private)
            agreement.doPhase(peerPublicKey, true)
            val sharedSecret = agreement.generateSecret()
            val keyBytes = hkdfSha256(sharedSecret, sessionId, HKDF_INFO, 32)
            sharedSecret.fill(0)
            return createSession(sessionId, keyBytes, isInitiator).also {
                keyBytes.fill(0)
            }
        }

        private fun createSession(
            sessionId: ByteArray,
            keyBytes: ByteArray,
            isInitiator: Boolean,
            sendCounter: ULong = 0uL,
            receiveCounter: ULong = 0uL,
        ): NfcSessionCrypto {
            val sendDirection = if (isInitiator) {
                DIRECTION_READER_TO_PHONE
            } else {
                DIRECTION_PHONE_TO_READER
            }
            val receiveDirection = if (isInitiator) {
                DIRECTION_PHONE_TO_READER
            } else {
                DIRECTION_READER_TO_PHONE
            }
            return NfcSessionCrypto(
                sessionId.copyOf(),
                keyBytes,
                sendDirection.toByte(),
                receiveDirection.toByte(),
                sendCounter,
                receiveCounter,
            )
        }

        private fun encodeHandshake(sessionId: ByteArray, publicKey: ByteArray): ByteArray {
            require(sessionId.size == SESSION_ID_LENGTH)
            require(publicKey.size == PUBLIC_KEY_LENGTH)
            return byteArrayOf(VERSION.toByte()) + sessionId + publicKey
        }

        private fun parseHandshake(payload: ByteArray): ParsedHandshake {
            require(payload.size == 1 + SESSION_ID_LENGTH + PUBLIC_KEY_LENGTH) {
                "Invalid NFC handshake length"
            }
            require(payload[0].toUByte().toInt() == VERSION) {
                "Unsupported NFC protocol version"
            }
            return ParsedHandshake(
                sessionId = payload.copyOfRange(1, 1 + SESSION_ID_LENGTH),
                publicKey = payload.copyOfRange(1 + SESSION_ID_LENGTH, payload.size),
            )
        }

        private fun encodePublicKey(keyPair: KeyPair): ByteArray {
            val publicKey = keyPair.public as ECPublicKey
            return byteArrayOf(0x04) +
                toFixedLength(publicKey.w.affineX, 32) +
                toFixedLength(publicKey.w.affineY, 32)
        }

        private fun decodePoint(encoded: ByteArray): ECPoint {
            require(encoded.size == PUBLIC_KEY_LENGTH && encoded[0] == 0x04.toByte()) {
                "Invalid uncompressed P-256 public key"
            }
            val x = BigInteger(1, encoded.copyOfRange(1, 33))
            val y = BigInteger(1, encoded.copyOfRange(33, 65))
            return ECPoint(x, y)
        }

        private fun toFixedLength(value: BigInteger, length: Int): ByteArray {
            val encoded = value.toByteArray()
            val unsigned = if (encoded.size > length) {
                encoded.copyOfRange(encoded.size - length, encoded.size)
            } else {
                encoded
            }
            require(unsigned.size <= length)
            return ByteArray(length).also {
                unsigned.copyInto(it, destinationOffset = length - unsigned.size)
            }
        }

        private fun encodeSequence(sequence: ULong): ByteArray {
            return ByteArray(SEQUENCE_LENGTH) { index ->
                (sequence shr ((SEQUENCE_LENGTH - 1 - index) * 8)).toByte()
            }
        }

        private fun decodeSequence(encoded: ByteArray): ULong {
            require(encoded.size == SEQUENCE_LENGTH)
            return encoded.fold(0uL) { value, byte ->
                (value shl 8) or byte.toUByte().toULong()
            }
        }

        private fun hkdfSha256(
            inputKeyMaterial: ByteArray,
            salt: ByteArray,
            info: ByteArray,
            length: Int,
        ): ByteArray {
            require(length in 1..32) { "This HKDF implementation supports one SHA-256 block" }

            val extract = Mac.getInstance(HKDF_ALGORITHM)
            extract.init(SecretKeySpec(salt, HKDF_ALGORITHM))
            val pseudoRandomKey = extract.doFinal(inputKeyMaterial)

            val expand = Mac.getInstance(HKDF_ALGORITHM)
            expand.init(SecretKeySpec(pseudoRandomKey, HKDF_ALGORITHM))
            expand.update(info)
            expand.update(1.toByte())
            val output = expand.doFinal().copyOf(length)
            pseudoRandomKey.fill(0)
            return output
        }
    }
}
