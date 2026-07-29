package de.infornautik.nfcauth

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject

class AuthDatabase(context: Context) :
    SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        private const val DATABASE_NAME = "auth.db"
        private const val DATABASE_VERSION = 2
        private const val TABLE_SERVICES = "services"

        private const val SERVICE_ID = "service_id"
        private const val SERVICE_NAME = "service_name"
        private const val OPERATOR_NAME = "operator_name"
        private const val IDENTITY_VERIFIED = "identity_verified"
        private const val USER_ID = "user_id"
        private const val USER_ALIAS = "user_alias"
        private const val PRIVACY_POLICY_URL = "privacy_policy_url"
        private const val PRIVACY_NOTICE_VERSION = "privacy_notice_version"
        private const val REQUESTED_FIELDS = "requested_fields"
        private const val PURPOSES = "purposes"
        private const val DELETION_CONTACT = "deletion_contact"
        private const val ENCRYPTION_FINGERPRINT = "encryption_fingerprint"
        private const val SIGNING_FINGERPRINT = "signing_fingerprint"
        private const val MANIFEST_HASH = "manifest_hash"
        private const val APPROVED_AT = "approved_at"

        private val columns = arrayOf(
            SERVICE_ID,
            SERVICE_NAME,
            OPERATOR_NAME,
            IDENTITY_VERIFIED,
            USER_ID,
            USER_ALIAS,
            PRIVACY_POLICY_URL,
            PRIVACY_NOTICE_VERSION,
            REQUESTED_FIELDS,
            PURPOSES,
            DELETION_CONTACT,
            ENCRYPTION_FINGERPRINT,
            SIGNING_FINGERPRINT,
            MANIFEST_HASH,
            APPROVED_AT,
        )
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE $TABLE_SERVICES (
                $SERVICE_ID TEXT PRIMARY KEY,
                $SERVICE_NAME TEXT NOT NULL,
                $OPERATOR_NAME TEXT NOT NULL,
                $IDENTITY_VERIFIED INTEGER NOT NULL,
                $USER_ID TEXT NOT NULL,
                $USER_ALIAS TEXT,
                $PRIVACY_POLICY_URL TEXT NOT NULL,
                $PRIVACY_NOTICE_VERSION TEXT NOT NULL,
                $REQUESTED_FIELDS TEXT NOT NULL,
                $PURPOSES TEXT NOT NULL,
                $DELETION_CONTACT TEXT NOT NULL,
                $ENCRYPTION_FINGERPRINT TEXT NOT NULL,
                $SIGNING_FINGERPRINT TEXT NOT NULL,
                $MANIFEST_HASH TEXT NOT NULL,
                $APPROVED_AT INTEGER NOT NULL
            )
            """.trimIndent(),
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            // Legacy registrations shared one signing key and had no authenticated
            // encryption identity. They cannot be migrated safely; users must
            // approve a new privacy-aware registration.
            db.execSQL("DROP TABLE IF EXISTS readers")
            db.execSQL("DROP TABLE IF EXISTS $TABLE_SERVICES")
            onCreate(db)
        }
    }

    fun getAllReaders(): List<ReaderInfo> {
        val readers = mutableListOf<ReaderInfo>()
        readableDatabase.query(
            TABLE_SERVICES,
            columns,
            null,
            null,
            null,
            null,
            "$SERVICE_NAME COLLATE NOCASE ASC",
        ).use { cursor ->
            while (cursor.moveToNext()) {
                cursor.toReaderInfoOrNull()?.let(readers::add)
            }
        }
        return readers
    }

    fun getReaderInfo(serviceId: String): ReaderInfo? =
        readableDatabase.query(
            TABLE_SERVICES,
            columns,
            "$SERVICE_ID = ?",
            arrayOf(serviceId),
            null,
            null,
            null,
        ).use { cursor ->
            if (cursor.moveToFirst()) cursor.toReaderInfoOrNull() else null
        }

    fun registerReader(reader: ReaderInfo): Boolean {
        val values = ContentValues().apply {
            put(SERVICE_ID, reader.serviceId)
            put(SERVICE_NAME, reader.serviceName)
            put(OPERATOR_NAME, reader.operatorName)
            put(IDENTITY_VERIFIED, if (reader.identityVerified) 1 else 0)
            put(USER_ID, reader.userId)
            if (reader.alias == null) putNull(USER_ALIAS) else put(USER_ALIAS, reader.alias)
            put(PRIVACY_POLICY_URL, reader.privacyPolicyUrl)
            put(PRIVACY_NOTICE_VERSION, reader.privacyNoticeVersion)
            put(REQUESTED_FIELDS, JSONArray(reader.requestedFields).toString())
            put(PURPOSES, JSONObject(reader.purposes).toString())
            put(DELETION_CONTACT, reader.deletionUrlOrContact)
            put(ENCRYPTION_FINGERPRINT, reader.encryptionKeyFingerprint)
            put(SIGNING_FINGERPRINT, reader.signingKeyFingerprint)
            put(MANIFEST_HASH, reader.manifestHash)
            put(APPROVED_AT, reader.approvedAt)
        }
        return writableDatabase.insertWithOnConflict(
            TABLE_SERVICES,
            null,
            values,
            SQLiteDatabase.CONFLICT_REPLACE,
        ) != -1L
    }

    fun deleteReader(serviceId: String): Boolean =
        writableDatabase.delete(TABLE_SERVICES, "$SERVICE_ID = ?", arrayOf(serviceId)) > 0

    private fun Cursor.toReaderInfoOrNull(): ReaderInfo? = try {
        val fieldsJson = JSONArray(getString(getColumnIndexOrThrow(REQUESTED_FIELDS)))
        val fields = (0 until fieldsJson.length()).map(fieldsJson::getString)
        val purposesJson = JSONObject(getString(getColumnIndexOrThrow(PURPOSES)))
        val purposes = linkedMapOf<String, String>()
        val purposeKeys = purposesJson.keys()
        while (purposeKeys.hasNext()) {
            val key = purposeKeys.next()
            purposes[key] = purposesJson.getString(key)
        }
        ReaderInfo(
            serviceId = getString(getColumnIndexOrThrow(SERVICE_ID)),
            serviceName = getString(getColumnIndexOrThrow(SERVICE_NAME)),
            operatorName = getString(getColumnIndexOrThrow(OPERATOR_NAME)),
            identityVerified = getInt(getColumnIndexOrThrow(IDENTITY_VERIFIED)) == 1,
            userId = getString(getColumnIndexOrThrow(USER_ID)),
            alias = getColumnIndexOrThrow(USER_ALIAS).let { index ->
                if (isNull(index)) null else getString(index)
            },
            privacyPolicyUrl = getString(getColumnIndexOrThrow(PRIVACY_POLICY_URL)),
            privacyNoticeVersion = getString(getColumnIndexOrThrow(PRIVACY_NOTICE_VERSION)),
            requestedFields = fields,
            purposes = purposes,
            deletionUrlOrContact = getString(getColumnIndexOrThrow(DELETION_CONTACT)),
            encryptionKeyFingerprint = getString(
                getColumnIndexOrThrow(ENCRYPTION_FINGERPRINT),
            ),
            signingKeyFingerprint = getString(getColumnIndexOrThrow(SIGNING_FINGERPRINT)),
            manifestHash = getString(getColumnIndexOrThrow(MANIFEST_HASH)),
            approvedAt = getLong(getColumnIndexOrThrow(APPROVED_AT)),
        )
    } catch (_: Exception) {
        null
    }
}
