package de.infornautik.nfcauth

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import java.security.KeyStore
import org.json.JSONObject
import java.util.UUID
import android.util.Base64
import java.io.File
import java.io.FileOutputStream
import java.io.FileInputStream
import java.io.ObjectOutputStream
import java.io.ObjectInputStream
import android.content.Intent
import android.os.Vibrator
import android.os.VibrationEffect
import android.content.Context


class CardEmulationAuthService : HostApduService() {
    private lateinit var keyManager: KeyManager
    private lateinit var authDatabase: AuthDatabase
    private var deviceUuid: String? = null
    private var pendingResponse: ByteArray? = null
    private var pendingResponseOffset = 0
    private var registrationDialog: RegistrationDialog? = null
    private lateinit var registrationDataManager: RegistrationDataManager
    private val authStateManager = BiometricAuthStateManager.getInstance()

    companion object {
        private const val TAG = "CardEmulationAuthService"
        private const val PENDING_REGISTRATION_FILE = "pending_registration.json"
        private val AID = byteArrayOf(0xF0.toByte(), 0x64.toByte(), 0x65.toByte(), 0x2E.toByte(), 0x69.toByte(), 0x6E.toByte(), 0x66.toByte(), 0x6F.toByte(), 0x72.toByte(), 0x6E.toByte(), 0x61.toByte(), 0x75.toByte(), 0x74.toByte(), 0x69.toByte(), 0x6B.toByte())
        private val CMD_SELECT_APDU = byteArrayOf(0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte())
        private val CMD_USER_REGISTRATION = byteArrayOf(0xD0.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte())
        private val CMD_USER_REGISTRATION_COMPLETE = byteArrayOf(0xD0.toByte(), 0x01.toByte(), 0x00.toByte(), 0x01.toByte())
        private val CMD_USER_AUTHENTICATION = byteArrayOf(0xD0.toByte(), 0x02.toByte(), 0x00.toByte(), 0x00.toByte())
        private val CMD_GET_RESPONSE = byteArrayOf(0x00.toByte(), 0xC0.toByte(), 0x00.toByte(), 0x00.toByte())
        private val CMD_USER_NOT_REGISTERED = byteArrayOf(0xD0.toByte(), 0x03.toByte(), 0x00.toByte(), 0x00.toByte())
        private val RESP_SUCCESS_SW = byteArrayOf(0x90.toByte(), 0x00.toByte())
        private val RESP_UNKNOWN_CMD_SW = byteArrayOf(0x00.toByte(), 0x00.toByte())
        private val RESP_ERROR_SW = byteArrayOf(0x67.toByte(), 0x00.toByte())
        private val RESP_BIOMETRIC_REQUIRED_SW = byteArrayOf(0x63.toByte(), 0x00.toByte())
        private val RESP_UNAUTHORIZED_SW = byteArrayOf(0x69.toByte(), 0x83.toByte())
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "CardEmulationService onCreate")

        // Initialize KeyManager
        keyManager = KeyManager(this)
        Log.d(TAG, "KeyManager initialized")

        // Initialize database
        authDatabase = AuthDatabase(this)
        Log.d(TAG, "Database initialized successfully")

        // Initialize registration data manager
        registrationDataManager = RegistrationDataManager(this)
        Log.d(TAG, "RegistrationDataManager initialized")
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "CardEmulationService onDestroy")
        // Clear pending data but keep authentication state
        pendingResponse = null
        pendingResponseOffset = 0
        authDatabase.close()
    }

    fun setPendingRegistrationData(data: JSONObject?) {
        try {
            if (data == null) {
                if (File(filesDir, PENDING_REGISTRATION_FILE).exists()) {
                    File(filesDir, PENDING_REGISTRATION_FILE).delete()
                    Log.d(TAG, "Deleted pending registration data")
                }
            } else {
                FileOutputStream(File(filesDir, PENDING_REGISTRATION_FILE)).use { fos ->
                    ObjectOutputStream(fos).writeObject(data.toString())
                }
                Log.d(TAG, "Saved pending registration data ${data.toString()}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error saving pending registration data", e)
        }
    }

    fun getPendingRegistrationData(): JSONObject? {
        return try {
            val file = File(filesDir, PENDING_REGISTRATION_FILE)
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

    private fun computeRegistrationComplete(): Boolean {
        Log.d(TAG, "Registration complete")
        val pendingRegistrationData = registrationDataManager.getPendingRegistrationData()
        if (pendingRegistrationData == null) {
            Log.e(TAG, "No pending registration data")
            return false
        }
        val userId = pendingRegistrationData.optString("user_id")
        val userName = pendingRegistrationData.optString("user_name")
        val readerId = pendingRegistrationData.optString("reader_id")
        val readerName = pendingRegistrationData.optString("reader_name")
        if (readerId.isBlank() || readerName.isBlank() || userId.isBlank() || userName.isBlank()) {
            Log.e(TAG, "Invalid registration complete data: $pendingRegistrationData")
            return false
        }
        authDatabase.registerReader(readerId, readerName, userId, userName)
        registrationDataManager.setPendingRegistrationData(null)
        return true
    }

    private fun showRegistrationDialog(readerId: String, readerName: String) {
        Log.d(TAG, "Showing registration dialog")
        vibrate()
        // Create an intent to launch the registration activity
        val registrationIntent = Intent(this, RegistrationActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("reader_id", readerId)
            putExtra("reader_name", readerName)
        }        
        startActivity(registrationIntent)
    }

    private fun showBiometricPrompt() {
        // Since we're in a service, we need to create a new activity to show the biometric prompt
        val intent = Intent(this, BiometricPromptActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
    }

    private fun showNotRegisteredDialog() {
        vibrate()
        val intent = Intent(this, NotRegisteredDialog::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
    }

    private fun computeRegistrationResponse(dataString: String): ByteArray {
        // Parse the registration request JSON
        val registrationRequest = JSONObject(dataString)
        val readerId = registrationRequest.optString("reader_id")
        val readerName = registrationRequest.optString("reader_name")
        val version = registrationRequest.optInt("version", -1)

        if (readerId.isBlank() || readerName.isBlank() || version == -1) {
            Log.e(TAG, "Invalid registration request: missing reader_id or reader_name or version")
            return RESP_UNKNOWN_CMD_SW
        }

        if (version != 1) {
            Log.e(TAG, "Unsupported version: $version")
            return RESP_UNKNOWN_CMD_SW
        }

        var pendingRegistrationData = registrationDataManager.getPendingRegistrationData()

        if (pendingRegistrationData == null || pendingRegistrationData.optString("reader_id") != readerId) {
            Log.d(TAG, "Starting new registration process for reader $readerId")
            
            // Show registration dialog
            showRegistrationDialog(readerId, readerName)
            Log.e(TAG, "Registration response pending")
            return RESP_SUCCESS_SW
        } else {
            // Continue the registration process
            Log.d(TAG, "Continuing registration process for reader $readerId, sending registration response: ${pendingRegistrationData}")
            return setPendingResponse(pendingRegistrationData.toString().toByteArray())
        }
    }

    private fun computeAuthenticationResponse(dataString: String): ByteArray {
        // Parse the authentication request JSON
        val authRequest = JSONObject(dataString)
        val readerId = authRequest.optString("reader_id")
        val nonce = authRequest.optString("nonce")
        val auth = authRequest.optString("auth")
        val version = authRequest.optInt("version", -1)
        if (readerId.isBlank() || nonce.isBlank() || auth.isBlank() || version == -1) {
            Log.e(TAG, "Invalid authentication request: missing reader_id or nonce or auth or version")
            return RESP_UNKNOWN_CMD_SW
        }

        if (version != 1) {
            Log.e(TAG, "Unsupported version: $version")
            return RESP_UNKNOWN_CMD_SW
        }

        // Get the user ID and private key from the database
        val readerInfo = authDatabase.getReaderInfo(readerId) ?: run {
            Log.e(TAG, "No reader info found in database")
            showNotRegisteredDialog()
            return RESP_UNAUTHORIZED_SW
        }

        if (auth == "background") {
            // Always authenticate
        } else if (auth == "biometric") {
            // Run biometric authentication
            if (!authStateManager.isAuthenticated()) {
                Log.d(TAG, "Not authenticated, showing biometric prompt")
                vibrate()
                // Show biometric prompt
                showBiometricPrompt()

                return RESP_BIOMETRIC_REQUIRED_SW
            }
        } else {
            return RESP_UNKNOWN_CMD_SW
        }
        
        val userId = readerInfo.userId
        
        // Sign the authentication request data
        val signature = keyManager.sign((dataString + userId).toByteArray())
        
        // Create authentication response
        val response = JSONObject().apply {
            put("user_id", userId)
            put("signature", signature)
        }

        vibrate()

        Log.d(TAG, "Successful authentication response: $response")
        return setPendingResponse(response.toString().toByteArray())
    }

    fun vibrate() {
        @Suppress("DEPRECATION")
        val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createOneShot(50, VibrationEffect.DEFAULT_AMPLITUDE))
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(50)
        }
    }

    fun setPendingResponse(response: ByteArray): ByteArray {
        pendingResponse = response
        pendingResponseOffset = 0
        if (pendingResponse?.size ?: 0 == 0) {
            return byteArrayOf(0x90.toByte(), 0x00.toByte())
        }
        if (pendingResponse?.size ?: 0 >= 256) {
            // too large to send in one go
            return byteArrayOf(0x61.toByte(), 0x00.toByte())
        }
        return byteArrayOf(0x61.toByte(), (pendingResponse?.size ?: 0).toByte())
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        try {
            Log.d(TAG, "Received APDU command: ${bytesToHex(commandApdu)}")
            
            // Check if it's a SELECT command
            if (commandApdu.size >= 4 && 
                commandApdu[0] == CMD_SELECT_APDU[0] && 
                commandApdu[1] == CMD_SELECT_APDU[1] && 
                commandApdu[2] == CMD_SELECT_APDU[2] && 
                commandApdu[3] == CMD_SELECT_APDU[3]) {
                
                Log.d(TAG, "Processing SELECT command")
                // Extract AID from SELECT command
                val aidLength = commandApdu[4].toInt()
                val aid = commandApdu.copyOfRange(5, 5 + aidLength)
                Log.d(TAG, "SELECT AID: ${bytesToHex(aid)}")
                
                // Check if AID matches
                if (aid.contentEquals(AID)) {
                    Log.d(TAG, "AID matches, sending success response")
                    vibrate()
                    return byteArrayOf(0x90.toByte(), 0x00.toByte())
                } else {
                    Log.e(TAG, "AID mismatch. Expected: ${bytesToHex(AID)}, Got: ${bytesToHex(aid)}")
                    return byteArrayOf(0x6A.toByte(), 0x82.toByte()) // File not found
                }
            }
            
            // Check for registration command
            if (commandApdu.size >= 4 && 
                commandApdu[0] == CMD_USER_REGISTRATION[0] && 
                commandApdu[1] == CMD_USER_REGISTRATION[1] && 
                commandApdu[2] == CMD_USER_REGISTRATION[2] && 
                commandApdu[3] == CMD_USER_REGISTRATION[3]) {
                
                Log.d(TAG, "Processing user registration command")
                // Extract registration data from command
                val dataLength = commandApdu[4].toInt()
                val dataBytes = commandApdu.copyOfRange(5, 5 + dataLength)
                val dataString = String(dataBytes)
                
                Log.d(TAG, "Registration data: $dataString")

                return computeRegistrationResponse(dataString)
            }

            // Check for registration complete command
            if (commandApdu.size >= 4 && 
                commandApdu[0] == CMD_USER_REGISTRATION_COMPLETE[0] && 
                commandApdu[1] == CMD_USER_REGISTRATION_COMPLETE[1] && 
                commandApdu[2] == CMD_USER_REGISTRATION_COMPLETE[2] && 
                commandApdu[3] == CMD_USER_REGISTRATION_COMPLETE[3]) {
                
                Log.d(TAG, "Processing user registration complete command")
                if (!computeRegistrationComplete()) {
                    Log.e(TAG, "Error computing registration complete")
                    return RESP_ERROR_SW
                }
                vibrate()
                return RESP_SUCCESS_SW
            }

            // Check for authentication command
            if (commandApdu.size >= 4 && 
                commandApdu[0] == CMD_USER_AUTHENTICATION[0] && 
                commandApdu[1] == CMD_USER_AUTHENTICATION[1] && 
                commandApdu[2] == CMD_USER_AUTHENTICATION[2] && 
                commandApdu[3] == CMD_USER_AUTHENTICATION[3]) {
                
                Log.d(TAG, "Processing user authentication command")

                // Extract authentication data from command
                val dataLength = commandApdu[4].toInt()
                val dataBytes = commandApdu.copyOfRange(5, 5 + dataLength)
                val dataString = String(dataBytes)
                Log.d(TAG, "Authentication data: $dataString")
                return computeAuthenticationResponse(dataString)
            }

            // Check for get response command
            if (commandApdu.size == 5 && 
                commandApdu[0] == CMD_GET_RESPONSE[0] && 
                commandApdu[1] == CMD_GET_RESPONSE[1] && 
                commandApdu[2] == CMD_GET_RESPONSE[2] && 
                commandApdu[3] == CMD_GET_RESPONSE[3]) {

                // Create a local copy of the pending response to avoid null checks
                val currentPendingResponse = pendingResponse ?: run {
                    Log.e(TAG, "No pending response to send")
                    return RESP_UNKNOWN_CMD_SW
                }
                
                Log.d(TAG, "Processing GET RESPONSE command")
                // Extract response length from command
                var responseLength = commandApdu[4].toUByte().toInt()
                if (responseLength == 0) {
                    responseLength = 256
                }
                Log.d(TAG, "Response length: $responseLength")

                responseLength = minOf(responseLength, currentPendingResponse.size - pendingResponseOffset)

                var responseBuffer = ByteArray(responseLength + 2)
                currentPendingResponse.copyInto(responseBuffer, 0, pendingResponseOffset, pendingResponseOffset + responseLength)
                pendingResponseOffset += responseLength
                if (pendingResponseOffset >= currentPendingResponse.size) {
                    // all data sent
                    responseBuffer[responseBuffer.size - 2] = 0x90.toByte()
                    responseBuffer[responseBuffer.size - 1] = 0x00.toByte()
                } else if (currentPendingResponse.size - pendingResponseOffset <= 256) {
                    // less than 256 bytes remaining
                    responseBuffer[responseBuffer.size - 2] = 0x61.toByte()
                    responseBuffer[responseBuffer.size - 1] = (currentPendingResponse.size - pendingResponseOffset).toByte()
                } else {
                    // more than 256 bytes remaining
                    responseBuffer[responseBuffer.size - 2] = 0x61.toByte()
                    responseBuffer[responseBuffer.size - 1] = 0x00.toByte()
                }
                Log.d(TAG, "Sending response: ${bytesToHex(responseBuffer)}")
                return responseBuffer
            }

            // Check for user not registered command
            if (commandApdu.size >= 4 && 
                commandApdu[0] == CMD_USER_NOT_REGISTERED[0] && 
                commandApdu[1] == CMD_USER_NOT_REGISTERED[1] && 
                commandApdu[2] == CMD_USER_NOT_REGISTERED[2] && 
                commandApdu[3] == CMD_USER_NOT_REGISTERED[3]) {
                Log.d(TAG, "Processing user not registered command")
                showNotRegisteredDialog()
                return RESP_SUCCESS_SW
            }

            // No support for read/write commands
            
            // If not a registration command, check for other commands
            Log.w(TAG, "Unknown command: ${bytesToHex(commandApdu)}")
            return RESP_UNKNOWN_CMD_SW
        } catch (e: Exception) {
            Log.e(TAG, "Error processing command", e)
            return byteArrayOf(0x6F.toByte(), 0x00.toByte())
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02X", b))
        }
        return sb.toString()
    }

    override fun onDeactivated(reason: Int) {
        deviceUuid = null
        pendingResponse = null
        pendingResponseOffset = 0
        authDatabase.close()
        Log.d(TAG, "CardEmulationService onDeactivated, reason: $reason")
    }
} 