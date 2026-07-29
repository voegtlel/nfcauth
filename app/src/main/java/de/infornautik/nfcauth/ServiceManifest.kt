package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec

data class ServiceManifest(
    val serviceId: String,
    val serviceName: String,
    val operatorName: String,
    val privacyPolicyUrl: String,
    val privacyNoticeVersion: String,
    val requestedFields: List<String>,
    val purposes: Map<String, String>,
    val deletionUrlOrContact: String,
    val encryptionPublicKey: String,
    val registrationNonce: String,
    val privacyNoticeMaterialChange: Boolean,
)

data class VerifiedServiceManifest(
    val manifest: ServiceManifest,
    val identityVerified: Boolean,
    val signingKeyFingerprint: String,
    val encryptionKeyFingerprint: String,
    val manifestHash: String,
)

class ManifestValidationException(message: String) : Exception(message)

object ServiceManifestParser {
    const val PROTOCOL_VERSION = 2
    const val FIELD_ALIAS = "alias"
    const val FIELD_SERVICE_USER_ID = "service_user_id"
    const val FIELD_AUTHENTICATION_PUBLIC_KEY = "authentication_public_key"

    private val supportedFields = setOf(
        FIELD_ALIAS,
        FIELD_SERVICE_USER_ID,
        FIELD_AUTHENTICATION_PUBLIC_KEY,
    )
    private val serviceIdPattern = Regex("[A-Za-z0-9._-]{3,128}")
    private val noncePattern = Regex("[A-Fa-f0-9]{32,128}")
    private val emailPattern = Regex("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")

    fun parseAndVerify(rawEnvelope: String): VerifiedServiceManifest {
        val envelope = try {
            JSONObject(rawEnvelope)
        } catch (_: Exception) {
            throw ManifestValidationException("The registration manifest is not valid JSON.")
        }
        if (strictInt(envelope, "protocol_version") != PROTOCOL_VERSION) {
            throw ManifestValidationException("The registration protocol version is not supported.")
        }

        val rawManifest = envelope.opt("manifest") as? JSONObject
            ?: throw ManifestValidationException("The signed registration manifest is missing.")
        val manifest = ServiceManifest(
            serviceId = requiredString(rawManifest, "service_id", 128),
            serviceName = requiredString(rawManifest, "service_name", 120),
            operatorName = requiredString(rawManifest, "operator_name", 120),
            privacyPolicyUrl = requiredString(rawManifest, "privacy_policy_url", 2048),
            privacyNoticeVersion = requiredString(rawManifest, "privacy_notice_version", 80),
            requestedFields = parseRequestedFields(rawManifest),
            purposes = parsePurposes(rawManifest),
            deletionUrlOrContact = requiredString(rawManifest, "data_deletion_url_or_contact", 2048),
            encryptionPublicKey = requiredString(rawManifest, "encryption_public_key", 4096),
            registrationNonce = requiredString(rawManifest, "registration_nonce", 128),
            privacyNoticeMaterialChange = optionalBoolean(
                rawManifest,
                "privacy_notice_material_change",
                false,
            ),
        )
        validateManifest(manifest)

        val signingKeyEncoded = requiredString(envelope, "manifest_signing_public_key", 4096)
        val signatureEncoded = requiredString(envelope, "manifest_signature", 4096)
        val signingKey = parseP256PublicKey(signingKeyEncoded, "manifest signing")
        val encryptionKey = parseP256PublicKey(manifest.encryptionPublicKey, "encryption")
        val canonical = canonicalBytes(manifest)
        val signatureBytes = decodeBase64(signatureEncoded, "manifest signature")
        val signatureValid = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(signingKey)
                update(canonical)
                verify(signatureBytes)
            }
        } catch (_: Exception) {
            false
        }
        if (!signatureValid) {
            throw ManifestValidationException("The registration manifest signature is invalid.")
        }

        val signingFingerprint = fingerprint(signingKey.encoded)
        val encryptionFingerprint = fingerprint(encryptionKey.encoded)
        return VerifiedServiceManifest(
            manifest = manifest,
            identityVerified = ServiceTrustRegistry.isTrusted(
                manifest.serviceId,
                signingFingerprint,
            ),
            signingKeyFingerprint = signingFingerprint,
            encryptionKeyFingerprint = encryptionFingerprint,
            manifestHash = fingerprint(canonical),
        )
    }

    fun parseEncryptionKey(encoded: String): PublicKey =
        parseP256PublicKey(encoded, "encryption")

    fun canonicalBytes(manifest: ServiceManifest): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { output ->
            output.writeString(manifest.serviceId)
            output.writeString(manifest.serviceName)
            output.writeString(manifest.operatorName)
            output.writeString(manifest.privacyPolicyUrl)
            output.writeString(manifest.privacyNoticeVersion)
            val fields = manifest.requestedFields.sorted()
            output.writeInt(fields.size)
            fields.forEach { output.writeString(it) }
            output.writeInt(fields.size)
            fields.forEach { field ->
                output.writeString(field)
                output.writeString(manifest.purposes.getValue(field))
            }
            output.writeString(manifest.deletionUrlOrContact)
            output.writeString(manifest.encryptionPublicKey)
            output.writeString(manifest.registrationNonce)
            output.writeBoolean(manifest.privacyNoticeMaterialChange)
        }
        return buffer.toByteArray()
    }

    fun displayName(field: String): String = when (field) {
        FIELD_ALIAS -> "Alias"
        FIELD_SERVICE_USER_ID -> "Service-specific user ID"
        FIELD_AUTHENTICATION_PUBLIC_KEY -> "Public authentication key"
        else -> field
    }

    fun changeReasons(existing: ReaderInfo?, verified: VerifiedServiceManifest): List<String> {
        if (existing == null) return emptyList()
        val manifest = verified.manifest
        val reasons = mutableListOf<String>()
        if (manifest.requestedFields.toSet() != existing.requestedFields.toSet()) {
            reasons += "requested data changed"
        }
        if (manifest.purposes != existing.purposes) reasons += "data purposes changed"
        if (manifest.operatorName != existing.operatorName) reasons += "operator changed"
        if (verified.encryptionKeyFingerprint != existing.encryptionKeyFingerprint) {
            reasons += "service encryption identity changed"
        }
        if (verified.signingKeyFingerprint != existing.signingKeyFingerprint) {
            reasons += "manifest signing identity changed"
        }
        if (manifest.privacyNoticeMaterialChange) reasons += "privacy notice marked materially changed"
        return reasons
    }

    private fun validateManifest(manifest: ServiceManifest) {
        if (!serviceIdPattern.matches(manifest.serviceId)) {
            throw ManifestValidationException("The service ID is malformed.")
        }
        if (!noncePattern.matches(manifest.registrationNonce)) {
            throw ManifestValidationException("The registration challenge is malformed.")
        }
        validateHttpsUrl(manifest.privacyPolicyUrl, "privacy-policy")
        validateDeletionContact(manifest.deletionUrlOrContact)

        if (manifest.requestedFields.isEmpty()) {
            throw ManifestValidationException("The service did not disclose any requested data.")
        }
        if (manifest.requestedFields.size != manifest.requestedFields.toSet().size) {
            throw ManifestValidationException("The requested-data list contains duplicates.")
        }
        val unsupported = manifest.requestedFields.filterNot(supportedFields::contains)
        if (unsupported.isNotEmpty()) {
            throw ManifestValidationException("The service requested unsupported data.")
        }
        if (!manifest.requestedFields.contains(FIELD_SERVICE_USER_ID) ||
            !manifest.requestedFields.contains(FIELD_AUTHENTICATION_PUBLIC_KEY)
        ) {
            throw ManifestValidationException(
                "A service-specific user ID and authentication key are required.",
            )
        }
        if (manifest.purposes.keys != manifest.requestedFields.toSet()) {
            throw ManifestValidationException("Every requested field must have exactly one purpose.")
        }
        if (manifest.purposes.values.any { it.isBlank() || it.length > 500 }) {
            throw ManifestValidationException("A disclosed data purpose is missing or too long.")
        }
    }

    private fun parseRequestedFields(json: JSONObject): List<String> {
        val array = json.optJSONArray("requested_fields")
            ?: throw ManifestValidationException("The requested-data list is missing.")
        return (0 until array.length()).map { index ->
            val value = array.opt(index)
            if (value !is String || value.isBlank() || value.length > 80) {
                throw ManifestValidationException("A requested field is malformed.")
            }
            value
        }
    }

    private fun parsePurposes(json: JSONObject): Map<String, String> {
        val rawPurposes = json.opt("purposes") as? JSONObject
            ?: throw ManifestValidationException("The field purposes are missing.")
        val purposes = linkedMapOf<String, String>()
        val keys = rawPurposes.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val value = rawPurposes.opt(key)
            if (value !is String) {
                throw ManifestValidationException("A field purpose is malformed.")
            }
            purposes[key] = value.trim()
        }
        return purposes
    }

    private fun requiredString(json: JSONObject, name: String, maxLength: Int): String {
        val value = json.opt(name)
        if (value !is String) {
            throw ManifestValidationException("Required metadata is missing or malformed.")
        }
        val trimmed = value.trim()
        if (trimmed.isEmpty() || trimmed.length > maxLength) {
            throw ManifestValidationException("Required metadata is missing or malformed.")
        }
        return trimmed
    }

    private fun strictInt(json: JSONObject, name: String): Int {
        val value = json.opt(name)
        if (value !is Number || value.toDouble() != value.toInt().toDouble()) {
            throw ManifestValidationException("The protocol version is missing or malformed.")
        }
        return value.toInt()
    }

    private fun optionalBoolean(json: JSONObject, name: String, default: Boolean): Boolean {
        if (!json.has(name)) return default
        return json.opt(name) as? Boolean
            ?: throw ManifestValidationException("The privacy-notice change marker is malformed.")
    }

    private fun validateHttpsUrl(value: String, label: String) {
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            throw ManifestValidationException("The $label URL is malformed.")
        }
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            uri.host.isNullOrBlank() ||
            uri.userInfo != null
        ) {
            throw ManifestValidationException("The $label URL must use HTTPS.")
        }
    }

    private fun validateDeletionContact(value: String) {
        if (emailPattern.matches(value)) return
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            throw ManifestValidationException("The deletion link or contact is malformed.")
        }
        val validHttps = uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.userInfo == null
        val validMailTo = uri.scheme.equals("mailto", ignoreCase = true) &&
            emailPattern.matches(uri.schemeSpecificPart)
        if (!validHttps && !validMailTo) {
            throw ManifestValidationException(
                "The deletion contact must be an HTTPS URL or email address.",
            )
        }
    }

    private fun parseP256PublicKey(encoded: String, label: String): ECPublicKey {
        val key = try {
            KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(decodeBase64(encoded, "$label key")))
        } catch (_: ManifestValidationException) {
            throw ManifestValidationException("The service $label key is malformed.")
        } catch (_: Exception) {
            throw ManifestValidationException("The service $label key is malformed.")
        }
        val ecKey = key as? ECPublicKey
            ?: throw ManifestValidationException("The service $label key must be an EC key.")
        if (!isP256(ecKey.params)) {
            throw ManifestValidationException("The service $label key must use P-256.")
        }
        return ecKey
    }

    private fun isP256(parameters: ECParameterSpec): Boolean {
        val expected = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
        return parameters.curve == expected.curve &&
            parameters.generator == expected.generator &&
            parameters.order == expected.order &&
            parameters.cofactor == expected.cofactor
    }

    private fun decodeBase64(value: String, label: String): ByteArray = try {
        Base64.decode(value, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
        throw ManifestValidationException("The $label is not valid Base64.")
    }

    private fun fingerprint(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(data)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun DataOutputStream.writeString(value: String) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        writeInt(bytes.size)
        write(bytes)
    }
}

/**
 * Verified means the manifest signing key is pinned by the app developer.
 * A valid self-signature protects manifest integrity but is deliberately shown
 * as "unverified" until a fingerprint is added here through a reviewed release.
 */
object ServiceTrustRegistry {
    private val trustedSigningFingerprints: Map<String, Set<String>> = emptyMap()

    fun isTrusted(serviceId: String, signingFingerprint: String): Boolean =
        trustedSigningFingerprints[serviceId]?.contains(signingFingerprint) == true
}
