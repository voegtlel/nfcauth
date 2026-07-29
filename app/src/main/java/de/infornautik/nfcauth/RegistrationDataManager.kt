package de.infornautik.nfcauth

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class RegistrationDataManager(context: Context) {
    companion object {
        private const val PENDING_REGISTRATION_FILE = "pending_registration_v2.json"
    }

    private val pendingFile = File(context.filesDir, PENDING_REGISTRATION_FILE)

    fun setPendingRegistrationData(data: JSONObject?) {
        if (data == null) {
            pendingFile.delete()
            return
        }
        pendingFile.writeText(data.toString(), Charsets.UTF_8)
    }

    fun hasPendingRegistrationData(): Boolean = pendingFile.isFile

    fun getPendingRegistrationData(): JSONObject? = try {
        if (!pendingFile.isFile) null else JSONObject(pendingFile.readText(Charsets.UTF_8))
    } catch (_: Exception) {
        pendingFile.delete()
        null
    }

    fun pendingResponseFor(serviceId: String, manifestHash: String): JSONObject? {
        val pending = getPendingRegistrationData() ?: return null
        if (pending.optString("service_id") != serviceId ||
            pending.optString("manifest_hash") != manifestHash
        ) {
            return null
        }
        return pending.optJSONObject("encrypted_response")
    }

    fun createPendingRecord(
        verified: VerifiedServiceManifest,
        userId: String,
        alias: String?,
        encryptedResponse: JSONObject,
        wasRegistered: Boolean,
    ): JSONObject {
        val manifest = verified.manifest
        return JSONObject().apply {
            put("service_id", manifest.serviceId)
            put("manifest_hash", verified.manifestHash)
            put("registration_nonce", manifest.registrationNonce)
            put("was_registered", wasRegistered)
            put("encrypted_response", encryptedResponse)
            put(
                "record",
                JSONObject().apply {
                    put("service_name", manifest.serviceName)
                    put("operator_name", manifest.operatorName)
                    put("identity_verified", verified.identityVerified)
                    put("user_id", userId)
                    if (alias != null) put("alias", alias)
                    put("privacy_policy_url", manifest.privacyPolicyUrl)
                    put("privacy_notice_version", manifest.privacyNoticeVersion)
                    put("requested_fields", JSONArray(manifest.requestedFields))
                    put("purposes", JSONObject(manifest.purposes))
                    put("deletion_contact", manifest.deletionUrlOrContact)
                    put("encryption_fingerprint", verified.encryptionKeyFingerprint)
                    put("signing_fingerprint", verified.signingKeyFingerprint)
                    put("approved_at", System.currentTimeMillis())
                },
            )
        }
    }

    fun readerInfoFromPending(pending: JSONObject): ReaderInfo? = try {
        val serviceId = pending.getString("service_id")
        val manifestHash = pending.getString("manifest_hash")
        val record = pending.getJSONObject("record")
        val fieldsArray = record.getJSONArray("requested_fields")
        val fields = (0 until fieldsArray.length()).map(fieldsArray::getString)
        val purposesJson = record.getJSONObject("purposes")
        val purposes = linkedMapOf<String, String>()
        val keys = purposesJson.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            purposes[key] = purposesJson.getString(key)
        }
        ReaderInfo(
            serviceId = serviceId,
            serviceName = record.getString("service_name"),
            operatorName = record.getString("operator_name"),
            identityVerified = record.getBoolean("identity_verified"),
            userId = record.getString("user_id"),
            alias = if (record.has("alias")) record.getString("alias") else null,
            privacyPolicyUrl = record.getString("privacy_policy_url"),
            privacyNoticeVersion = record.getString("privacy_notice_version"),
            requestedFields = fields,
            purposes = purposes,
            deletionUrlOrContact = record.getString("deletion_contact"),
            encryptionKeyFingerprint = record.getString("encryption_fingerprint"),
            signingKeyFingerprint = record.getString("signing_fingerprint"),
            manifestHash = manifestHash,
            approvedAt = record.getLong("approved_at"),
        )
    } catch (_: Exception) {
        null
    }

    fun cancelPendingRegistration(keyManager: KeyManager) {
        val pending = getPendingRegistrationData()
        if (pending != null) {
            val serviceId = pending.optString("service_id")
            if (serviceId.isNotBlank()) {
                keyManager.discardPendingSessionKey(
                    serviceId,
                    deleteSigningKey = !pending.optBoolean("was_registered", false),
                )
            }
        }
        setPendingRegistrationData(null)
    }
}
