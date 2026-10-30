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
        error("Protocol-v4 database has no legacy migration path")

    fun getAllReaders(): List<ReaderInfo> {
        val readers = mutableListOf<ReaderInfo>()
        readableDatabase.query("services", null, null, null, null, null, "service_name COLLATE NOCASE").use {
            while (it.moveToNext()) it.toReader()?.let(readers::add)
        }
        return readers
    }

    fun getReaderInfo(serviceOrigin: String, serviceId: String, profile: String): ReaderInfo? =
        readableDatabase.query(
            "services", null, "service_origin=? AND service_id=? AND authentication_profile=?",
            arrayOf(serviceOrigin, serviceId, profile), null, null, null,
        ).use { if (it.moveToFirst()) it.toReader() else null }

    fun registerReader(reader: ReaderInfo): Boolean {
        val values = ContentValues().apply {
            put("service_id", reader.serviceId)
            put("authentication_profile", reader.authenticationProfile)
            put("service_origin", reader.serviceOrigin)
            put("service_name", reader.serviceName)
            put("operator_name", reader.operatorName)
            put("credential_id", reader.credentialId)
            put("privacy_policy_url", reader.privacyPolicyUrl)
            put("privacy_notice_version", reader.privacyNoticeVersion)
            put("requested_fields", JSONArray(reader.requestedFields).toString())
            put("purposes", JSONObject(reader.purposes).toString())
            put("deletion_contact", reader.deletionUrlOrContact)
            put("certificate_fingerprint", reader.certificateFingerprint)
            put("verified_domain", reader.verifiedDomain)
            put("manifest_hash", reader.manifestHash)
            put("approved_at", reader.approvedAt)
            put("registration_expires_at", reader.registrationExpiresAt)
            put("allowed_audiences", JSONArray(reader.allowedAudiences).toString())
            put("allowed_scopes", JSONArray(reader.allowedScopes).toString())
        }
        return writableDatabase.insertWithOnConflict(
            "services", null, values, SQLiteDatabase.CONFLICT_REPLACE,
        ) != -1L
    }

    fun deleteReader(serviceOrigin: String, serviceId: String, profile: String): Boolean =
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

    private fun Cursor.toReader(): ReaderInfo? = try {
        fun string(name: String) = getString(getColumnIndexOrThrow(name))
        val fieldsJson = JSONArray(string("requested_fields"))
        val fields = (0 until fieldsJson.length()).map(fieldsJson::getString)
        val purposeJson = JSONObject(string("purposes"))
        val purposes = purposeJson.keys().asSequence().associateWith(purposeJson::getString)
        ReaderInfo(
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
