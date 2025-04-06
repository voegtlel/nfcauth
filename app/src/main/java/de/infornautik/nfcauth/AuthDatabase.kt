package de.infornautik.nfcauth

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log




class AuthDatabase(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {
    companion object {
        private const val DATABASE_NAME = "auth.db"
        private const val DATABASE_VERSION = 1
        private const val TABLE_READERS = "readers"
        private const val TAG = "AuthDatabase"

        private const val COLUMN_READER_ID = "reader_id"
        private const val COLUMN_READER_NAME = "reader_name"
        private const val COLUMN_USER_ID = "user_id"
        private const val COLUMN_USER_NAME = "user_name"
    }

    override fun onCreate(db: SQLiteDatabase) {
        Log.d(TAG, "Creating database tables")
        
        val createReadersTable = """
            CREATE TABLE $TABLE_READERS (
                $COLUMN_READER_ID TEXT PRIMARY KEY,
                $COLUMN_READER_NAME TEXT NOT NULL,
                $COLUMN_USER_ID TEXT NOT NULL,
                $COLUMN_USER_NAME TEXT NOT NULL
            )
        """.trimIndent()
        
        db.execSQL(createReadersTable)
        Log.d(TAG, "Created readers table")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        Log.d(TAG, "Upgrading database from $oldVersion to $newVersion")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_READERS")
        onCreate(db)
    }

    fun getAllReaders(): List<ReaderInfo> {
        Log.d(TAG, "Getting all readers")
        
        val db = this.readableDatabase
        val cursor = db.query(TABLE_READERS, arrayOf(COLUMN_READER_ID, COLUMN_READER_NAME, COLUMN_USER_ID, COLUMN_USER_NAME), null, null, null, null, null)
        
        val readers = mutableListOf<ReaderInfo>()
        while (cursor.moveToNext()) {
            val readerId = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_READER_ID))
            val readerName = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_READER_NAME))
            val userId = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_USER_ID))
            val userName = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_USER_NAME))
            readers.add(ReaderInfo(readerId, readerName, userId, userName))
        }

        cursor.close()
        Log.d(TAG, "Found ${readers.size} readers")
        return readers
    }

    fun deleteReader(readerId: String): Boolean {
        Log.d(TAG, "Deleting reader: $readerId")
        
        val db = this.writableDatabase
        val success = db.delete(TABLE_READERS, "$COLUMN_READER_ID = ?", arrayOf(readerId)) != 0
        
        Log.d(TAG, "Reader deletion ${if (success) "successful" else "failed"}")
        return success
    }

    fun registerReader(readerId: String, readerName: String, userId: String, userName: String): Boolean {
        Log.d(TAG, "Registering reader: $readerName ($readerId) for user: $userId")
        
        val db = this.writableDatabase
        val values = ContentValues().apply {
            put(COLUMN_READER_ID, readerId)
            put(COLUMN_READER_NAME, readerName)
            put(COLUMN_USER_ID, userId)
            put(COLUMN_USER_NAME, userName)
        }
        
        val success = try {
            db.insertOrThrow(TABLE_READERS, null, values) != -1L
        } catch (e: Exception) {
            Log.e(TAG, "Error registering reader", e)
            false
        }
        
        Log.d(TAG, "Reader registration ${if (success) "successful" else "failed"}")
        return success
    }

    fun getReaderInfo(readerId: String): ReaderInfo? {
        Log.d(TAG, "Getting reader info for reader ID: $readerId")
        
        val db = this.readableDatabase
        val cursor = db.query(
            TABLE_READERS,
            arrayOf(COLUMN_READER_ID, COLUMN_READER_NAME, COLUMN_USER_ID, COLUMN_USER_NAME),
            "$COLUMN_READER_ID = ?",
            arrayOf(readerId),
            null,
            null,
            null
        )
        
        return if (cursor.moveToFirst()) {
            val readerInfo = ReaderInfo(
                readerId = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_READER_ID)),
                readerName = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_READER_NAME)),
                userId = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_USER_ID)),
                userName = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_USER_NAME))
            )
            cursor.close()
            Log.d(TAG, "Found reader info: $readerInfo")
            readerInfo
        } else {
            cursor.close()
            Log.d(TAG, "No reader info found for reader ID: $readerId")
            null
        }
    }
} 