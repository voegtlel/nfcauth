package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.URI
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

data class ServiceManifest(
    val serviceOrigin: String,
    val serviceId: String,
    val serviceName: String,
    val operatorName: String,
    val privacyPolicyUrl: String,
    val privacyNoticeVersion: String,
    val requestedFields: List<String>,
    val purposes: Map<String, String>,
    val deletionUrlOrContact: String,
    val authenticationProfile: String,
    val encryptionPublicKey: String,
    val privacyNoticeMaterialChange: Boolean,
)

data class VerifiedServiceManifest(
    val manifest: ServiceManifest,
    val manifestHash: String,
    val encryptionKeyFingerprint: String,
    val certificateFingerprint: String,
    val verifiedDomain: String,
)

class ManifestValidationException(message: String, cause: Throwable? = null) : Exception(message, cause)

object ServiceManifestParser {
    const val PROTOCOL_VERSION = 3
    const val FIELD_ALIAS = "alias"
    const val FIELD_AUTHENTICATION_PUBLIC_KEY = "authentication_public_key"
    const val PROFILE_POSSESSION = "possession"
    const val PROFILE_BIOMETRIC = "biometric"
    private val fields = setOf(FIELD_ALIAS, FIELD_AUTHENTICATION_PUBLIC_KEY)
    private val profiles = setOf(PROFILE_POSSESSION, PROFILE_BIOMETRIC)

    fun parse(value: JSONObject): ServiceManifest {
        try {
            val origin = value.getString("service_origin")
            val originUri = URI(origin)
            require(
                originUri.scheme == "https" && !originUri.host.isNullOrBlank() &&
                    originUri.userInfo == null && (originUri.path.isNullOrBlank() || originUri.path == "/") &&
                    originUri.query == null && originUri.fragment == null,
            )
            val policy = value.getString("privacy_policy_url")
            val policyUri = URI(policy)
            require(
                policyUri.scheme == "https" && !policyUri.host.isNullOrBlank() &&
                    policyUri.userInfo == null,
            )
            val requestedJson = value.getJSONArray("requested_fields")
            val requested = (0 until requestedJson.length()).map(requestedJson::getString)
            require(requested.isNotEmpty() && requested.toSet().size == requested.size)
            require(requested.all(fields::contains) && requested.contains(FIELD_AUTHENTICATION_PUBLIC_KEY))
            val purposeObject = value.getJSONObject("purposes")
            val purposes = requested.associateWith {
                purposeObject.getString(it).also { purpose -> require(purpose.isNotBlank()) }
            }
            require(purposeObject.length() == requested.size)
            val profile = value.getString("authentication_profile")
            require(profile in profiles)
            val manifest = ServiceManifest(
                origin.trimEnd('/'),
                value.getString("service_id").also { require(it.isNotBlank()) },
                value.getString("service_name").also { require(it.isNotBlank()) },
                value.getString("operator_name").also { require(it.isNotBlank()) },
                policy,
                value.getString("privacy_notice_version").also { require(it.isNotBlank()) },
                requested,
                purposes,
                value.getString("data_deletion_url_or_contact").also { require(it.isNotBlank()) },
                profile,
                value.getString("encryption_public_key"),
                value.optBoolean("privacy_notice_material_change", false),
            )
            parseEncryptionKey(manifest.encryptionPublicKey)
            return manifest
        } catch (error: Exception) {
            throw ManifestValidationException("The service registration manifest is missing or malformed.", error)
        }
    }

    fun canonicalBytes(manifest: ServiceManifest): ByteArray =
        ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeByte(PROTOCOL_VERSION)
                listOf(
                    manifest.serviceOrigin,
                    manifest.serviceId,
                    manifest.serviceName,
                    manifest.operatorName,
                    manifest.privacyPolicyUrl,
                    manifest.privacyNoticeVersion,
                    manifest.authenticationProfile,
                ).forEach { writeString(output, it) }
                val requested = manifest.requestedFields.sorted()
                output.writeInt(requested.size)
                requested.forEach { writeString(output, it) }
                output.writeInt(requested.size)
                requested.forEach {
                    writeString(output, it)
                    writeString(output, manifest.purposes.getValue(it))
                }
                writeString(output, manifest.deletionUrlOrContact)
                writeString(output, manifest.encryptionPublicKey)
                output.writeByte(if (manifest.privacyNoticeMaterialChange) 1 else 0)
            }
        }.toByteArray()

    fun hash(manifest: ServiceManifest) = sha256(canonicalBytes(manifest))

    fun parseEncryptionKey(value: String): PublicKey {
        val key = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(Base64.decode(value, Base64.NO_WRAP)),
        )
        require(key is ECPublicKey && key.params.curve.field.fieldSize == 256)
        return key
    }

    fun fingerprint(publicKey: PublicKey) = sha256(publicKey.encoded)

    fun changeReasons(existing: ReaderInfo?, verified: VerifiedServiceManifest): List<String> {
        if (existing == null) return emptyList()
        val manifest = verified.manifest
        return buildList {
            if (existing.serviceOrigin != manifest.serviceOrigin) add("service domain")
            if (existing.operatorName != manifest.operatorName) add("operator")
            if (existing.authenticationProfile != manifest.authenticationProfile) add("authentication profile")
            if (existing.requestedFields != manifest.requestedFields || existing.purposes != manifest.purposes) {
                add("requested data or purposes")
            }
            if (existing.encryptionKeyFingerprint != verified.encryptionKeyFingerprint) add("encryption identity")
            if (manifest.privacyNoticeMaterialChange ||
                existing.privacyNoticeVersion != manifest.privacyNoticeVersion
            ) {
                add("privacy notice")
            }
        }
    }

    fun displayName(field: String) = when (field) {
        FIELD_ALIAS -> "Alias"
        FIELD_AUTHENTICATION_PUBLIC_KEY -> "Profile-specific public authentication key"
        else -> field
    }

    private fun writeString(output: DataOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        output.writeInt(bytes.size)
        output.write(bytes)
    }

    private fun sha256(value: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
