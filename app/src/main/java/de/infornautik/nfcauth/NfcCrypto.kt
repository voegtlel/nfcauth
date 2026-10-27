package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class RegistrationEncryptionResult(val envelope: JSONObject, val sessionKey: ByteArray)

object NfcCrypto {
    private val random = SecureRandom()

    fun encryptRegistration(
        verified: VerifiedServiceManifest,
        credentialId: String,
        registrationNonce: String,
        fields: JSONObject,
    ): RegistrationEncryptionResult {
        val manifest = verified.manifest
        val ephemeral = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"), random)
            generateKeyPair()
        }
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(ephemeral.private)
        agreement.doPhase(ServiceManifestParser.parseEncryptionKey(manifest.encryptionPublicKey), true)
        val shared = agreement.generateSecret()
        val key = hkdf(
            shared,
            hex(verified.manifestHash),
            ("nfcauth-v3-credential|" + manifest.serviceId + "|" + credentialId + "|" +
                manifest.authenticationProfile).toByteArray(),
        )
        shared.fill(0)
        val plaintext = JSONObject()
            .put("protocol_version", 3)
            .put("service_id", manifest.serviceId)
            .put("credential_id", credentialId)
            .put("authentication_profile", manifest.authenticationProfile)
            .put("registration_nonce", registrationNonce)
            .put("fields", fields)
        val encrypted = encryptJson(
            plaintext,
            key,
            aad("registration-response", manifest.serviceId, credentialId, manifest.authenticationProfile, 0, verified.manifestHash),
        )
        return RegistrationEncryptionResult(
            JSONObject()
                .put("protocol_version", 3)
                .put("service_id", manifest.serviceId)
                .put("credential_id", credentialId)
                .put("authentication_profile", manifest.authenticationProfile)
                .put("key_epoch", 0)
                .put("manifest_hash", verified.manifestHash)
                .put("phone_ephemeral_public_key", Base64.encodeToString(ephemeral.public.encoded, Base64.NO_WRAP))
                .put("iv", encrypted.getString("iv"))
                .put("ciphertext", encrypted.getString("ciphertext")),
            key,
        )
    }

    fun decryptRegistrationAcknowledgement(
        envelope: JSONObject,
        service: ReaderInfo,
        registrationNonce: String,
        key: ByteArray,
    ): JSONObject {
        requireIdentity(envelope, service, 0)
        require(envelope.getString("manifest_hash") == service.manifestHash)
        val result = decryptJson(
            envelope,
            key,
            aad(
                "registration-ack", service.serviceId, service.credentialId,
                service.authenticationProfile, 0, service.manifestHash,
            ),
        )
        require(
            result.getInt("protocol_version") == 3 &&
                result.getString("status") == "registered" &&
                result.getString("registration_nonce") == registrationNonce,
        )
        return result
    }

    fun decryptAuthenticationRequest(
        envelope: JSONObject,
        service: ReaderInfo,
        key: ByteArray,
        epoch: Int,
    ): JSONObject {
        requireIdentity(envelope, service, epoch)
        return decryptJson(
            envelope, key,
            aad("authentication-request", service.serviceId, service.credentialId, service.authenticationProfile, epoch),
        )
    }

    fun encryptAuthenticationResponse(
        service: ReaderInfo,
        key: ByteArray,
        epoch: Int,
        plaintext: JSONObject,
    ): JSONObject {
        val encrypted = encryptJson(
            plaintext, key,
            aad("authentication-response", service.serviceId, service.credentialId, service.authenticationProfile, epoch),
        )
        return identityEnvelope(service, epoch)
            .put("iv", encrypted.getString("iv"))
            .put("ciphertext", encrypted.getString("ciphertext"))
    }

    fun deriveRotatedKey(service: ReaderInfo, currentKey: ByteArray, epoch: Int, nonce: String) =
        hkdf(
            currentKey,
            hex(nonce),
            (
                "nfcauth-v3-key-update|" + service.serviceId + "|" + service.credentialId + "|" +
                    service.authenticationProfile + "|" + (epoch + 1)
                ).toByteArray(),
        )

    fun decryptKeyCommit(
        envelope: JSONObject,
        service: ReaderInfo,
        key: ByteArray,
        epoch: Int,
    ): JSONObject {
        requireIdentity(envelope, service, epoch)
        return decryptJson(
            envelope, key,
            aad("key-commit", service.serviceId, service.credentialId, service.authenticationProfile, epoch),
        )
    }

    fun encryptKeyCommitAck(
        service: ReaderInfo,
        key: ByteArray,
        epoch: Int,
        rotationId: String,
    ): JSONObject {
        val plaintext = JSONObject()
            .put("protocol_version", 3)
            .put("status", "key-commit-acknowledged")
            .put("service_id", service.serviceId)
            .put("credential_id", service.credentialId)
            .put("authentication_profile", service.authenticationProfile)
            .put("key_epoch", epoch)
            .put("rotation_id", rotationId)
        val encrypted = encryptJson(
            plaintext, key,
            aad("key-commit-ack", service.serviceId, service.credentialId, service.authenticationProfile, epoch),
        )
        return identityEnvelope(service, epoch)
            .put("iv", encrypted.getString("iv"))
            .put("ciphertext", encrypted.getString("ciphertext"))
    }

    fun authenticationSignaturePayload(
        service: ReaderInfo,
        epoch: Int,
        nonce: String,
        transportBinding: String,
    ): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { output ->
            listOf(
                "nfcauth-v3-auth", service.serviceOrigin, service.serviceId, service.credentialId,
                service.authenticationProfile, epoch.toString(), nonce, transportBinding, service.manifestHash,
            ).forEach {
                val encoded = it.toByteArray(StandardCharsets.UTF_8)
                output.writeInt(encoded.size)
                output.write(encoded)
            }
        }
    }.toByteArray()

    private fun identityEnvelope(service: ReaderInfo, epoch: Int) = JSONObject()
        .put("protocol_version", 3)
        .put("service_id", service.serviceId)
        .put("credential_id", service.credentialId)
        .put("authentication_profile", service.authenticationProfile)
        .put("key_epoch", epoch)

    private fun requireIdentity(envelope: JSONObject, service: ReaderInfo, epoch: Int) {
        require(
            envelope.getInt("protocol_version") == 3 &&
                envelope.getString("service_id") == service.serviceId &&
                envelope.getString("credential_id") == service.credentialId &&
                envelope.getString("authentication_profile") == service.authenticationProfile &&
                envelope.getInt("key_epoch") == epoch,
        )
    }

    private fun encryptJson(value: JSONObject, key: ByteArray, aad: String): JSONObject {
        val iv = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad.toByteArray())
        return JSONObject()
            .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            .put(
                "ciphertext",
                Base64.encodeToString(cipher.doFinal(value.toString().toByteArray()), Base64.NO_WRAP),
            )
    }

    private fun decryptJson(value: JSONObject, key: ByteArray, aad: String): JSONObject {
        val iv = Base64.decode(value.getString("iv"), Base64.NO_WRAP)
        require(iv.size == 12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad.toByteArray())
        return JSONObject(String(cipher.doFinal(Base64.decode(value.getString("ciphertext"), Base64.NO_WRAP))))
    }

    private fun aad(
        purpose: String, serviceId: String, credentialId: String, profile: String, epoch: Int,
        suffix: String = "",
    ): String {
        val base = "nfcauth-v3|" + purpose + "|" + serviceId + "|" + credentialId + "|" + profile + "|" + epoch
        return if (suffix.isEmpty()) base else base + "|" + suffix
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = extract.doFinal(ikm)
        val expand = Mac.getInstance("HmacSHA256")
        expand.init(SecretKeySpec(prk, "HmacSHA256"))
        expand.update(info)
        expand.update(1)
        return expand.doFinal().also { prk.fill(0) }
    }

    private fun hex(value: String) = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
