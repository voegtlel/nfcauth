package de.infornautik.nfcauth

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class RegistrationDataManager(context: Context) {
    private val pendingFile = File(context.filesDir, "pending-registration-v3.json")

    fun setPendingRegistrationData(data: JSONObject?) {
        if (data == null) pendingFile.delete() else pendingFile.writeText(data.toString())
    }
    fun hasPendingRegistrationData() = pendingFile.isFile
    fun getPendingRegistrationData(): JSONObject? = try {
        if (pendingFile.isFile) JSONObject(pendingFile.readText()) else null
    } catch (_: Exception) {
        pendingFile.delete()
        null
    }

    fun pendingResponseFor(
        serviceId: String,
        profile: String,
        credentialId: String,
        nonce: String,
        manifestHash: String,
    ): JSONObject? {
        val value = getPendingRegistrationData() ?: return null
        return if (
            value.optString("service_id") == serviceId &&
            value.optString("authentication_profile") == profile &&
            value.optString("credential_id") == credentialId &&
            value.optString("registration_nonce") == nonce &&
            value.optString("manifest_hash") == manifestHash
        ) {
            value.optJSONObject("encrypted_response")
        } else {
            null
        }
    }

    fun createPendingRecord(
        verified: VerifiedServiceManifest,
        credentialId: String,
        registrationNonce: String,
        alias: String?,
        encryptedResponse: JSONObject,
        wasRegistered: Boolean,
    ): JSONObject {
        val manifest = verified.manifest
        return JSONObject()
            .put("service_id", manifest.serviceId)
            .put("authentication_profile", manifest.authenticationProfile)
            .put("credential_id", credentialId)
            .put("manifest_hash", verified.manifestHash)
            .put("registration_nonce", registrationNonce)
            .put("was_registered", wasRegistered)
            .put("encrypted_response", encryptedResponse)
            .put(
                "record",
                JSONObject()
                    .put("service_origin", manifest.serviceOrigin)
                    .put("service_name", manifest.serviceName)
                    .put("operator_name", manifest.operatorName)
                    .put("alias", alias)
                    .put("privacy_policy_url", manifest.privacyPolicyUrl)
                    .put("privacy_notice_version", manifest.privacyNoticeVersion)
                    .put("requested_fields", JSONArray(manifest.requestedFields))
                    .put("purposes", JSONObject(manifest.purposes))
                    .put("deletion_contact", manifest.deletionUrlOrContact)
                    .put("encryption_fingerprint", verified.encryptionKeyFingerprint)
                    .put("certificate_fingerprint", verified.certificateFingerprint)
                    .put("verified_domain", verified.verifiedDomain)
                    .put("approved_at", System.currentTimeMillis()),
            )
    }

    fun readerInfoFromPending(value: JSONObject): ReaderInfo? = try {
        val record = value.getJSONObject("record")
        val fieldsJson = record.getJSONArray("requested_fields")
        val fields = (0 until fieldsJson.length()).map(fieldsJson::getString)
        val purposeJson = record.getJSONObject("purposes")
        val purposes = purposeJson.keys().asSequence().associateWith(purposeJson::getString)
        ReaderInfo(
            record.getString("service_origin"),
            value.getString("service_id"),
            record.getString("service_name"),
            record.getString("operator_name"),
            value.getString("credential_id"),
            value.getString("authentication_profile"),
            if (record.isNull("alias")) null else record.getString("alias"),
            record.getString("privacy_policy_url"),
            record.getString("privacy_notice_version"),
            fields,
            purposes,
            record.getString("deletion_contact"),
            record.getString("encryption_fingerprint"),
            record.getString("certificate_fingerprint"),
            record.getString("verified_domain"),
            value.getString("manifest_hash"),
            record.getLong("approved_at"),
        )
    } catch (_: Exception) {
        null
    }

    fun cancelPendingRegistration(keyManager: KeyManager) {
        getPendingRegistrationData()?.let {
            val serviceId = it.optString("service_id")
            val profile = it.optString("authentication_profile")
            if (serviceId.isNotBlank() && profile.isNotBlank()) {
                keyManager.discardPendingRegistration(
                    serviceId, profile, !it.optBoolean("was_registered", false),
                )
            }
        }
        setPendingRegistrationData(null)
    }
}
