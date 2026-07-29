package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class RegistrationEncryptionResult(
    val envelope: JSONObject,
    val sessionKey: ByteArray,
)

object NfcCrypto {
    private const val AES_GCM_TAG_BITS = 128
    private const val AES_GCM_IV_BYTES = 12
    private val secureRandom = SecureRandom()

    fun encryptRegistration(
        verified: VerifiedServiceManifest,
        plaintext: JSONObject,
    ): RegistrationEncryptionResult {
        val ephemeralGenerator = KeyPairGenerator.getInstance("EC")
        ephemeralGenerator.initialize(ECGenParameterSpec("secp256r1"), secureRandom)
        val ephemeral = ephemeralGenerator.generateKeyPair()
        val agreement = KeyAgreement.getInstance("ECDH").apply {
            init(ephemeral.private)
            doPhase(
                ServiceManifestParser.parseEncryptionKey(
                    verified.manifest.encryptionPublicKey,
                ),
                true,
            )
        }
        val sharedSecret = agreement.generateSecret()
        val sessionKey = hkdfSha256(
            inputKeyMaterial = sharedSecret,
            salt = hexToBytes(verified.manifestHash),
            info = "nfcauth-v2-session|${verified.manifest.serviceId}"
                .toByteArray(StandardCharsets.UTF_8),
            outputLength = 32,
        )
        sharedSecret.fill(0)

        val encrypted = encryptJson(
            plaintext,
            sessionKey,
            registrationAad(verified.manifest.serviceId, verified.manifestHash),
        )
        return RegistrationEncryptionResult(
            envelope = JSONObject().apply {
                put("protocol_version", ServiceManifestParser.PROTOCOL_VERSION)
                put("service_id", verified.manifest.serviceId)
                put("manifest_hash", verified.manifestHash)
                put(
                    "phone_ephemeral_public_key",
                    Base64.encodeToString(ephemeral.public.encoded, Base64.NO_WRAP),
                )
                put("iv", encrypted.getString("iv"))
                put("ciphertext", encrypted.getString("ciphertext"))
            },
            sessionKey = sessionKey,
        )
    }

    fun encryptAuthenticationResponse(
        service: ReaderInfo,
        sessionKey: ByteArray,
        plaintext: JSONObject,
    ): JSONObject {
        val encrypted = encryptJson(
            plaintext,
            sessionKey,
            authenticationResponseAad(service.serviceId),
        )
        return JSONObject().apply {
            put("protocol_version", ServiceManifestParser.PROTOCOL_VERSION)
            put("service_id", service.serviceId)
            put("encryption_key_fingerprint", service.encryptionKeyFingerprint)
            put("iv", encrypted.getString("iv"))
            put("ciphertext", encrypted.getString("ciphertext"))
        }
    }

    fun decryptAuthenticationRequest(
        envelope: JSONObject,
        service: ReaderInfo,
        sessionKey: ByteArray,
    ): JSONObject {
        validateEnvelopeIdentity(envelope, service)
        return decryptJson(
            envelope,
            sessionKey,
            authenticationRequestAad(service.serviceId),
        )
    }

    fun decryptRegistrationAcknowledgement(
        envelope: JSONObject,
        serviceId: String,
        manifestHash: String,
        sessionKey: ByteArray,
    ): JSONObject {
        if (strictInt(envelope, "protocol_version") != ServiceManifestParser.PROTOCOL_VERSION ||
            strictString(envelope, "service_id") != serviceId ||
            strictString(envelope, "manifest_hash") != manifestHash
        ) {
            throw SecurityException("Registration acknowledgement is for another service.")
        }
        return decryptJson(
            envelope,
            sessionKey,
            registrationAcknowledgementAad(serviceId, manifestHash),
        )
    }

    fun authenticationSignaturePayload(
        serviceId: String,
        nonce: String,
        authMode: String,
        userId: String,
    ): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { output ->
            listOf("nfcauth-v2-auth", serviceId, nonce, authMode, userId).forEach { value ->
                val bytes = value.toByteArray(StandardCharsets.UTF_8)
                output.writeInt(bytes.size)
                output.write(bytes)
            }
        }
        return buffer.toByteArray()
    }

    private fun validateEnvelopeIdentity(envelope: JSONObject, service: ReaderInfo) {
        if (strictInt(envelope, "protocol_version") != ServiceManifestParser.PROTOCOL_VERSION ||
            strictString(envelope, "service_id") != service.serviceId ||
            strictString(envelope, "encryption_key_fingerprint") !=
            service.encryptionKeyFingerprint
        ) {
            throw SecurityException("Authentication envelope identity mismatch.")
        }
    }

    private fun encryptJson(plaintext: JSONObject, key: ByteArray, aad: ByteArray): JSONObject {
        val iv = ByteArray(AES_GCM_IV_BYTES).also(secureRandom::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(AES_GCM_TAG_BITS, iv),
            )
            updateAAD(aad)
        }
        val ciphertext = cipher.doFinal(plaintext.toString().toByteArray(StandardCharsets.UTF_8))
        return JSONObject().apply {
            put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
        }
    }

    private fun decryptJson(envelope: JSONObject, key: ByteArray, aad: ByteArray): JSONObject {
        val iv = decodeBase64(strictString(envelope, "iv"))
        val ciphertext = decodeBase64(strictString(envelope, "ciphertext"))
        if (iv.size != AES_GCM_IV_BYTES || ciphertext.size <= AES_GCM_TAG_BITS / 8) {
            throw SecurityException("Encrypted payload is malformed.")
        }
        val plaintext = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(AES_GCM_TAG_BITS, iv),
            )
            updateAAD(aad)
            doFinal(ciphertext)
        }
        return try {
            JSONObject(String(plaintext, StandardCharsets.UTF_8))
        } finally {
            plaintext.fill(0)
        }
    }

    private fun hkdfSha256(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudorandomKey = mac.doFinal(inputKeyMaterial)
        val output = ByteArrayOutputStream()
        var previous = ByteArray(0)
        var counter = 1
        while (output.size() < outputLength) {
            mac.init(SecretKeySpec(pseudorandomKey, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            output.write(previous)
            counter += 1
        }
        pseudorandomKey.fill(0)
        previous.fill(0)
        return output.toByteArray().copyOf(outputLength)
    }

    private fun strictString(json: JSONObject, name: String): String =
        (json.opt(name) as? String)?.takeIf(String::isNotBlank)
            ?: throw SecurityException("Encrypted envelope is malformed.")

    private fun strictInt(json: JSONObject, name: String): Int =
        (json.opt(name) as? Number)?.toInt()
            ?: throw SecurityException("Encrypted envelope is malformed.")

    private fun decodeBase64(value: String): ByteArray = try {
        Base64.decode(value, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
        throw SecurityException("Encrypted envelope is malformed.")
    }

    private fun hexToBytes(value: String): ByteArray {
        if (value.length % 2 != 0) throw SecurityException("Fingerprint is malformed.")
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun registrationAad(serviceId: String, manifestHash: String) =
        "nfcauth-v2|registration-response|$serviceId|$manifestHash"
            .toByteArray(StandardCharsets.UTF_8)

    private fun registrationAcknowledgementAad(serviceId: String, manifestHash: String) =
        "nfcauth-v2|registration-ack|$serviceId|$manifestHash"
            .toByteArray(StandardCharsets.UTF_8)

    private fun authenticationRequestAad(serviceId: String) =
        "nfcauth-v2|authentication-request|$serviceId"
            .toByteArray(StandardCharsets.UTF_8)

    private fun authenticationResponseAad(serviceId: String) =
        "nfcauth-v2|authentication-response|$serviceId"
            .toByteArray(StandardCharsets.UTF_8)
}
