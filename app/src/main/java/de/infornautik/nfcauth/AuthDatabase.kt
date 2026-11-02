package de.infornautik.nfcauth

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject

class AuthDatabase(context: Context) : SQLiteOpenHelper(context, "auth-v4.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE services (
              service_id TEXT NOT NULL,
              authentication_profile TEXT NOT NULL,
              service_origin TEXT NOT NULL,
              service_name TEXT NOT NULL,
              operator_name TEXT NOT NULL,
              credential_id TEXT NOT NULL,
              privacy_policy_url TEXT NOT NULL,
              privacy_notice_version TEXT NOT NULL,
              requested_fields TEXT NOT NULL,
              purposes TEXT NOT NULL,
              deletion_contact TEXT NOT NULL,
              certificate_fingerprint TEXT NOT NULL,
              verified_domain TEXT NOT NULL,
              manifest_hash TEXT NOT NULL,
              approved_at INTEGER NOT NULL,
              registration_expires_at INTEGER NOT NULL,
              allowed_audiences TEXT NOT NULL,
              allowed_scopes TEXT NOT NULL,
              PRIMARY KEY(service_origin, service_id, authentication_profile)
            )
            """.trimIndent(),
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) =
        error("Database schema upgrades are unsupported")

    fun getAllRegistrations(): List<ServiceRegistration> {
        val registrations = mutableListOf<ServiceRegistration>()
        readableDatabase.query("services", null, null, null, null, null, "service_name COLLATE NOCASE").use {
            while (it.moveToNext()) it.toRegistration()?.let(registrations::add)
        }
        return registrations
    }

    fun getRegistration(serviceOrigin: String, serviceId: String, profile: String): ServiceRegistration? =
        readableDatabase.query(
            "services", null, "service_origin=? AND service_id=? AND authentication_profile=?",
            arrayOf(serviceOrigin, serviceId, profile), null, null, null,
        ).use { if (it.moveToFirst()) it.toRegistration() else null }

    fun saveRegistration(registration: ServiceRegistration): Boolean {
        val values = ContentValues().apply {
            put("service_id", registration.serviceId)
            put("authentication_profile", registration.authenticationProfile)
            put("service_origin", registration.serviceOrigin)
            put("service_name", registration.serviceName)
            put("operator_name", registration.operatorName)
            put("credential_id", registration.credentialId)
            put("privacy_policy_url", registration.privacyPolicyUrl)
            put("privacy_notice_version", registration.privacyNoticeVersion)
            put("requested_fields", JSONArray(registration.requestedFields).toString())
            put("purposes", JSONObject(registration.purposes).toString())
            put("deletion_contact", registration.deletionUrlOrContact)
            put("certificate_fingerprint", registration.certificateFingerprint)
            put("verified_domain", registration.verifiedDomain)
            put("manifest_hash", registration.manifestHash)
            put("approved_at", registration.approvedAt)
            put("registration_expires_at", registration.registrationExpiresAt)
            put("allowed_audiences", JSONArray(registration.allowedAudiences).toString())
            put("allowed_scopes", JSONArray(registration.allowedScopes).toString())
        }
        return writableDatabase.insertWithOnConflict(
            "services", null, values, SQLiteDatabase.CONFLICT_REPLACE,
        ) != -1L
    }

    fun deleteRegistration(serviceOrigin: String, serviceId: String, profile: String): Boolean =
        writableDatabase.delete(
            "services",
            "service_origin=? AND service_id=? AND authentication_profile=?",
            arrayOf(serviceOrigin, serviceId, profile),
        ) > 0

    fun updateRegistrationExpiration(
        serviceOrigin: String,
        serviceId: String,
        profile: String,
        expiresAt: Long,
        certificateFingerprint: String,
        verifiedDomain: String,
    ): Boolean = writableDatabase.update(
        "services",
        ContentValues().apply {
            put("registration_expires_at", expiresAt)
            put("certificate_fingerprint", certificateFingerprint)
            put("verified_domain", verifiedDomain)
        },
        "service_origin=? AND service_id=? AND authentication_profile=?",
        arrayOf(serviceOrigin, serviceId, profile),
    ) == 1

    private fun Cursor.toRegistration(): ServiceRegistration? = try {
        fun string(name: String) = getString(getColumnIndexOrThrow(name))
        val fieldsJson = JSONArray(string("requested_fields"))
        val fields = (0 until fieldsJson.length()).map(fieldsJson::getString)
        val purposeJson = JSONObject(string("purposes"))
        val purposes = purposeJson.keys().asSequence().associateWith(purposeJson::getString)
        ServiceRegistration(
            string("service_origin"), string("service_id"), string("service_name"),
            string("operator_name"), string("credential_id"), string("authentication_profile"),
            string("privacy_policy_url"), string("privacy_notice_version"), fields, purposes,
            string("deletion_contact"),
            string("certificate_fingerprint"), string("verified_domain"),
            string("manifest_hash"), getLong(getColumnIndexOrThrow("approved_at")),
            getLong(getColumnIndexOrThrow("registration_expires_at")),
            JSONArray(string("allowed_audiences")).let { values ->
                (0 until values.length()).map(values::getString)
            },
            JSONArray(string("allowed_scopes")).let { values ->
                (0 until values.length()).map(values::getString)
            },
        )
    } catch (_: Exception) {
        null
    }
}
