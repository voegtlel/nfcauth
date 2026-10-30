package de.infornautik.nfcauth

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.security.MessageDigest
import java.util.Locale

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
    val supportedProfiles: List<String>,
    val allowedAudiences: List<String>,
    val allowedScopes: List<String>,
    val registrationEndpoint: String,
    val renewalEndpoint: String,
    val registrationLifetimeDays: Int,
)

data class VerifiedServiceManifest(
    val manifest: ServiceManifest,
    val manifestHash: String,
    val certificateFingerprint: String,
    val verifiedDomain: String,
)

class ManifestValidationException(message: String, cause: Throwable? = null) : Exception(message, cause)

object ServiceManifestParser {
    const val PROTOCOL_VERSION = 4
    const val FIELD_AUTHENTICATION_PUBLIC_KEY = "authentication_public_key"
    const val FIELD_PROVIDER_ASSIGNED_CREDENTIAL_ID = "provider_assigned_credential_id"
    const val PROFILE_POSSESSION = "possession"
    const val PROFILE_BIOMETRIC = "biometric"
    private val fields = setOf(FIELD_AUTHENTICATION_PUBLIC_KEY, FIELD_PROVIDER_ASSIGNED_CREDENTIAL_ID)
    private val profiles = setOf(PROFILE_POSSESSION, PROFILE_BIOMETRIC)
    private val manifestKeys = setOf(
        "protocol_version",
        "service_origin",
        "service_id",
        "service_name",
        "operator_name",
        "privacy_policy_url",
        "privacy_notice_version",
        "requested_fields",
        "purposes",
        "data_deletion_url_or_contact",
        "supported_assurance_profiles",
        "allowed_audiences",
        "allowed_scopes",
        "registration_endpoint",
        "renewal_endpoint",
        "registration_lifetime_days",
    )

    fun parse(value: JSONObject): ServiceManifest = try {
        require(value.keys().asSequence().toSet() == manifestKeys)
        require(value.getInt("protocol_version") == PROTOCOL_VERSION)
        val origin = canonicalOrigin(value.getString("service_origin"))
        val policy = httpsUrl(value.getString("privacy_policy_url"))
        val registration = httpsUrl(value.getString("registration_endpoint"))
        val renewal = httpsUrl(value.getString("renewal_endpoint"))
        require(URI(registration).host == URI(origin).host && URI(renewal).host == URI(origin).host)
        val registrationLifetimeDays = value.getInt("registration_lifetime_days")
        require(registrationLifetimeDays in 365..730)
        val requested = value.getJSONArray("requested_fields").strings()
        require(requested.isNotEmpty() && requested.toSet().size == requested.size && requested.all(fields::contains))
        require(requested.contains(FIELD_AUTHENTICATION_PUBLIC_KEY))
        val purposesObject = value.getJSONObject("purposes")
        val purposes = requested.associateWith {
            purposesObject.getString(it).also { purpose -> require(purpose.isNotBlank()) }
        }
        require(purposesObject.length() == requested.size)
        val supportedProfiles = value.getJSONArray("supported_assurance_profiles").strings()
        require(supportedProfiles.isNotEmpty() && supportedProfiles.toSet().size == supportedProfiles.size)
        require(supportedProfiles.all(profiles::contains))
        val audiences = value.getJSONArray("allowed_audiences").strings()
        val scopes = value.getJSONArray("allowed_scopes").strings()
        require(audiences.isNotEmpty() && scopes.isNotEmpty())
        require(audiences.all(String::isNotBlank) && scopes.all(String::isNotBlank))
        ServiceManifest(
            origin,
            value.getString("service_id").also { require(it.isNotBlank()) },
            value.getString("service_name").also { require(it.isNotBlank()) },
            value.getString("operator_name").also { require(it.isNotBlank()) },
            policy,
            value.getString("privacy_notice_version").also { require(it.isNotBlank()) },
            requested,
            purposes,
            validateDeletionUrlOrContact(value.getString("data_deletion_url_or_contact")),
            supportedProfiles,
            audiences.distinct().sorted(),
            scopes.distinct().sorted(),
            registration,
            renewal,
            registrationLifetimeDays,
        )
    } catch (error: Exception) {
        throw ManifestValidationException("The provider manifest is missing or malformed.", error)
    }

    fun hash(value: JSONObject): String = sha256(
        AuthorizationRequestVerifier.canonical(value).toByteArray(Charsets.UTF_8),
    )

    fun displayName(field: String) = when (field) {
        FIELD_AUTHENTICATION_PUBLIC_KEY -> "Profile-specific public authentication key"
        FIELD_PROVIDER_ASSIGNED_CREDENTIAL_ID -> "Provider-assigned credential ID"
        else -> field
    }

    fun canonicalOrigin(value: String): String {
        val uri = URI(value)
        require(
            uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank() && uri.userInfo == null &&
                (uri.path.isNullOrBlank() || uri.path == "/") && uri.query == null && uri.fragment == null,
        )
        val port = if (uri.port == 443) -1 else uri.port
        return URI(
            "https",
            null,
            uri.host.lowercase(Locale.ROOT),
            port,
            null,
            null,
            null,
        ).toASCIIString()
    }

    private fun httpsUrl(value: String): String {
        val uri = URI(value)
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null)
        return value
    }

    internal fun validateDeletionUrlOrContact(value: String): String {
        require(value == value.trim() && value.length in 1..2048)
        val address = when {
            EMAIL_ADDRESS.matches(value) -> value
            value.startsWith("mailto:", ignoreCase = true) -> value.substringAfter(':')
            else -> return httpsUrl(value)
        }
        require(EMAIL_ADDRESS.matches(address))
        return value
    }

    private fun JSONArray.strings() = (0 until length()).map(::getString)
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private val EMAIL_ADDRESS = Regex("^[A-Za-z0-9.!#$%&'*+/=?^_{}|~-]+@[A-Za-z0-9.-]+$")
}
