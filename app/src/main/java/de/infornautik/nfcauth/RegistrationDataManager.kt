package de.infornautik.nfcauth

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

class RegistrationDataManager(private val context: Context) {
    companion object {
        private const val TAG = "RegistrationDataManager"
        private const val PENDING_REGISTRATION_FILE = "pending_registration.json"
    }

    fun setPendingRegistrationData(data: JSONObject?) {
        try {
            if (data == null) {
                if (File(context.filesDir, PENDING_REGISTRATION_FILE).exists()) {
                    File(context.filesDir, PENDING_REGISTRATION_FILE).delete()
                    Log.d(TAG, "Deleted pending registration data")
                }
            } else {
                FileOutputStream(File(context.filesDir, PENDING_REGISTRATION_FILE)).use { fos ->
                    ObjectOutputStream(fos).writeObject(data.toString())
                }
                Log.d(TAG, "Saved pending registration data ${data.toString()}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error saving pending registration data", e)
        }
    }

    fun hasPendingRegistrationData(): Boolean {
        return File(context.filesDir, PENDING_REGISTRATION_FILE).exists()
    }

    fun getPendingRegistrationData(): JSONObject? {
        return try {
            val file = File(context.filesDir, PENDING_REGISTRATION_FILE)
            if (!file.exists()) {
                return null
            }
            val data = FileInputStream(file).use { fis ->
                ObjectInputStream(fis).readObject() as String
            }
            JSONObject(data)
        } catch (e: Exception) {
            Log.e(TAG, "Error loading pending registration data", e)
            null
        }
    }
} 