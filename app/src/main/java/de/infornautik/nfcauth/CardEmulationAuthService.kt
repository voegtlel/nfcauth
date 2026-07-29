package de.infornautik.nfcauth

import android.content.Context
import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import org.json.JSONObject
import java.io.ByteArrayOutputStream

class CardEmulationAuthService : HostApduService() {
    private lateinit var keyManager: KeyManager
    private lateinit var authDatabase: AuthDatabase
    private lateinit var registrationDataManager: RegistrationDataManager
    private val authStateManager = BiometricAuthStateManager.getInstance()

    private var pendingResponse: ByteArray? = null
    private var pendingResponseOffset = 0
    private var incomingInstruction: Int? = null
    private var incomingSequence = 0
    private var incomingPayload = ByteArrayOutputStream()
    private var activeTransportSession: NfcSessionCrypto? = null

    override fun onCreate() {
        super.onCreate()
        keyManager = KeyManager(this)
        authDatabase = AuthDatabase(this)
        registrationDataManager = RegistrationDataManager(this)
    }

    override fun onDestroy() {
        clearTransientState()
        authDatabase.close()
        super.onDestroy()
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        return try {
            when {
                isSelectCommand(commandApdu) -> processSelect(commandApdu)
                commandApdu.size < 5 -> RESP_WRONG_LENGTH
                isGetResponseCommand(commandApdu) -> processGetResponse(commandApdu)
                commandApdu[0] != PROPRIETARY_CLASS -> RESP_UNKNOWN_COMMAND
                commandApdu[1] == INS_SESSION_INIT -> processSessionInit(commandApdu)
                commandApdu[1] == INS_REGISTRATION -> processIncomingChunk(
                    commandApdu,
                    INS_REGISTRATION.toInt() and 0xff,
                    PURPOSE_REGISTRATION,
                    ::computeRegistrationResponse,
                )
                commandApdu[1] == INS_AUTHENTICATION -> processIncomingChunk(
                    commandApdu,
                    INS_AUTHENTICATION.toInt() and 0xff,
                    PURPOSE_AUTHENTICATION,
                    ::computeAuthenticationResponse,
                )
                commandApdu[1] == INS_REGISTRATION_ACK -> processIncomingChunk(
                    commandApdu,
                    INS_REGISTRATION_ACK.toInt() and 0xff,
                    PURPOSE_REGISTRATION_COMPLETE,
                    ::computeRegistrationComplete,
                )
                commandApdu[1] == INS_USER_NOT_REGISTERED &&
                    activeTransportSession != null -> {
                    showNotRegisteredDialog()
                    RESP_SUCCESS
                }
                else -> RESP_UNKNOWN_COMMAND
            }
        } catch (_: Exception) {
            resetIncomingRequest()
            RESP_ERROR
        }
    }

    override fun onDeactivated(reason: Int) {
        clearTransientState()
    }

    private fun computeRegistrationResponse(rawEnvelope: String): ByteArray {
        val verified = try {
            ServiceManifestParser.parseAndVerify(rawEnvelope)
        } catch (_: ManifestValidationException) {
            return RESP_INVALID_DATA
        }

        registrationDataManager.pendingResponseFor(
            verified.manifest.serviceId,
            verified.manifestHash,
        )?.let { response ->
            return setEncryptedPendingResponse(
                response.toString().toByteArray(Charsets.UTF_8),
                PURPOSE_REGISTRATION,
            )
        }

        // Do not let a second service replace a transfer the user already approved.
        if (registrationDataManager.hasPendingRegistrationData()) {
            return RESP_CONDITIONS_NOT_SATISFIED
        }

        vibrate()
        startActivity(
            Intent(this, RegistrationActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(RegistrationActivity.EXTRA_SIGNED_MANIFEST, rawEnvelope)
            },
        )
        return RESP_SUCCESS
    }

    private fun computeRegistrationComplete(rawEnvelope: String): ByteArray {
        val pending = registrationDataManager.getPendingRegistrationData()
            ?: return RESP_CONDITIONS_NOT_SATISFIED
        val serviceId = pending.optString("service_id")
        val manifestHash = pending.optString("manifest_hash")
        val registrationNonce = pending.optString("registration_nonce")
        if (serviceId.isBlank() || manifestHash.isBlank() || registrationNonce.isBlank()) {
            return RESP_INVALID_DATA
        }
        val sessionKey = keyManager.getPendingSessionKey(serviceId)
            ?: return RESP_CONDITIONS_NOT_SATISFIED

        val acknowledgement = try {
            NfcCrypto.decryptRegistrationAcknowledgement(
                JSONObject(rawEnvelope),
                serviceId,
                manifestHash,
                sessionKey,
            )
        } catch (_: Exception) {
            return RESP_SECURITY_STATUS_NOT_SATISFIED
        } finally {
            sessionKey.fill(0)
        }
        if (acknowledgement.optString("status") != "registered" ||
            acknowledgement.optString("registration_nonce") != registrationNonce ||
            acknowledgement.optString("service_id") != serviceId
        ) {
            return RESP_SECURITY_STATUS_NOT_SATISFIED
        }

        val reader = registrationDataManager.readerInfoFromPending(pending)
            ?: return RESP_INVALID_DATA
        return try {
            keyManager.commitPendingSessionKey(serviceId)
            if (!authDatabase.registerReader(reader)) {
                return RESP_ERROR
            }
            registrationDataManager.setPendingRegistrationData(null)
            vibrate()
            RESP_SUCCESS
        } catch (_: Exception) {
            RESP_ERROR
        }
    }

    private fun computeAuthenticationResponse(rawEnvelope: String): ByteArray {
        val envelope = try {
            JSONObject(rawEnvelope)
        } catch (_: Exception) {
            return RESP_INVALID_DATA
        }
        val serviceId = envelope.opt("service_id") as? String
            ?: return RESP_INVALID_DATA
        val reader = authDatabase.getReaderInfo(serviceId) ?: run {
            showNotRegisteredDialog()
            return RESP_UNAUTHORIZED
        }
        val sessionKey = keyManager.getSessionKey(serviceId)
            ?: return RESP_UNAUTHORIZED
        val request = try {
            NfcCrypto.decryptAuthenticationRequest(envelope, reader, sessionKey)
        } catch (_: Exception) {
            sessionKey.fill(0)
            return RESP_SECURITY_STATUS_NOT_SATISFIED
        }

        val nonce = request.opt("nonce") as? String
        val authMode = request.opt("auth") as? String
        val requestServiceId = request.opt("service_id") as? String
        val requestVersion = (request.opt("protocol_version") as? Number)?.toInt()
        if (nonce.isNullOrBlank() ||
            authMode.isNullOrBlank() ||
            requestServiceId != serviceId ||
            requestVersion != ServiceManifestParser.PROTOCOL_VERSION
        ) {
            sessionKey.fill(0)
            return RESP_INVALID_DATA
        }

        when (authMode) {
            "background" -> Unit
            "biometric" -> if (!authStateManager.isAuthenticated()) {
                sessionKey.fill(0)
                vibrate()
                startActivity(
                    Intent(this, BiometricPromptActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    },
                )
                return RESP_BIOMETRIC_REQUIRED
            }
            else -> {
                sessionKey.fill(0)
                return RESP_INVALID_DATA
            }
        }

        val signature = try {
            keyManager.sign(
                serviceId,
                NfcCrypto.authenticationSignaturePayload(
                    serviceId,
                    nonce,
                    authMode,
                    reader.userId,
                ),
            )
        } catch (_: Exception) {
            sessionKey.fill(0)
            return RESP_ERROR
        }
        val plaintextResponse = JSONObject().apply {
            put("protocol_version", ServiceManifestParser.PROTOCOL_VERSION)
            put("service_id", serviceId)
            put("nonce", nonce)
            put("user_id", reader.userId)
            put("signature", signature)
        }
        val encryptedResponse = try {
            NfcCrypto.encryptAuthenticationResponse(reader, sessionKey, plaintextResponse)
        } catch (_: Exception) {
            sessionKey.fill(0)
            return RESP_ERROR
        }
        sessionKey.fill(0)
        vibrate()
        return setEncryptedPendingResponse(
            encryptedResponse.toString().toByteArray(Charsets.UTF_8),
            PURPOSE_AUTHENTICATION,
        )
    }

    private fun processIncomingChunk(
        command: ByteArray,
        instruction: Int,
        purpose: String,
        onComplete: (String) -> ByteArray,
    ): ByteArray {
        val transportSession = activeTransportSession
            ?: return RESP_SECURITY_STATUS_NOT_SATISFIED
        val sequence = command[2].toInt() and 0xff
        val flags = command[3].toInt() and 0xff
        if (flags != FLAG_FINAL && flags != FLAG_MORE) {
            resetIncomingRequest()
            return RESP_INVALID_DATA
        }
        val length = command[4].toInt() and 0xff
        if (command.size != length + 5) {
            resetIncomingRequest()
            return RESP_WRONG_LENGTH
        }

        if (sequence == 0) {
            resetIncomingRequest()
            incomingInstruction = instruction
        }
        if (incomingInstruction != instruction || sequence != incomingSequence) {
            resetIncomingRequest()
            return RESP_INVALID_DATA
        }
        if (incomingPayload.size() + length > MAX_INCOMING_PAYLOAD_BYTES) {
            resetIncomingRequest()
            return RESP_WRONG_LENGTH
        }
        incomingPayload.write(command, 5, length)

        if (flags == FLAG_MORE) {
            incomingSequence += 1
            if (incomingSequence > 255) {
                resetIncomingRequest()
                return RESP_WRONG_LENGTH
            }
            return RESP_SUCCESS
        }

        val encryptedPayload = incomingPayload.toByteArray()
        resetIncomingRequest()
        val plaintext = try {
            transportSession.decrypt(encryptedPayload, purpose)
        } catch (_: Exception) {
            return RESP_SECURITY_STATUS_NOT_SATISFIED
        }
        return try {
            onComplete(String(plaintext, Charsets.UTF_8))
        } finally {
            plaintext.fill(0)
        }
    }

    private fun processSessionInit(command: ByteArray): ByteArray {
        if (command[2] != 0x00.toByte() || command[3] != 0x00.toByte()) {
            return RESP_INVALID_DATA
        }
        val length = command[4].toInt() and 0xff
        if (command.size != length + 5) return RESP_WRONG_LENGTH
        return try {
            val accepted = NfcSessionCrypto.accept(command.copyOfRange(5, command.size))
            activeTransportSession = accepted.session
            resetIncomingRequest()
            setPendingResponse(accepted.response)
        } catch (_: Exception) {
            activeTransportSession = null
            RESP_SECURITY_STATUS_NOT_SATISFIED
        }
    }

    private fun processGetResponse(command: ByteArray): ByteArray {
        val response = pendingResponse ?: return RESP_CONDITIONS_NOT_SATISFIED
        var requested = command[4].toInt() and 0xff
        if (requested == 0) requested = 256
        val remaining = response.size - pendingResponseOffset
        if (remaining <= 0) {
            pendingResponse = null
            pendingResponseOffset = 0
            return RESP_CONDITIONS_NOT_SATISFIED
        }

        val responseLength = minOf(requested, remaining)
        val responseBuffer = ByteArray(responseLength + 2)
        response.copyInto(
            responseBuffer,
            destinationOffset = 0,
            startIndex = pendingResponseOffset,
            endIndex = pendingResponseOffset + responseLength,
        )
        pendingResponseOffset += responseLength
        val bytesRemaining = response.size - pendingResponseOffset
        if (bytesRemaining == 0) {
            responseBuffer[responseLength] = 0x90.toByte()
            responseBuffer[responseLength + 1] = 0x00.toByte()
            pendingResponse = null
            pendingResponseOffset = 0
        } else {
            responseBuffer[responseLength] = 0x61.toByte()
            responseBuffer[responseLength + 1] =
                if (bytesRemaining >= 256) 0 else bytesRemaining.toByte()
        }
        return responseBuffer
    }

    private fun setPendingResponse(response: ByteArray): ByteArray {
        pendingResponse = response
        pendingResponseOffset = 0
        return when {
            response.isEmpty() -> RESP_SUCCESS
            response.size >= 256 -> byteArrayOf(0x61.toByte(), 0x00.toByte())
            else -> byteArrayOf(0x61.toByte(), response.size.toByte())
        }
    }

    private fun setEncryptedPendingResponse(plaintext: ByteArray, purpose: String): ByteArray {
        val session = activeTransportSession
            ?: return RESP_SECURITY_STATUS_NOT_SATISFIED
        return try {
            setPendingResponse(session.encrypt(plaintext, purpose))
        } finally {
            plaintext.fill(0)
        }
    }

    private fun processSelect(command: ByteArray): ByteArray {
        if (command.size < 5) return RESP_WRONG_LENGTH
        val aidLength = command[4].toInt() and 0xff
        if (command.size < 5 + aidLength) return RESP_WRONG_LENGTH
        val aid = command.copyOfRange(5, 5 + aidLength)
        return if (aid.contentEquals(AID)) {
            clearTransientState()
            vibrate()
            RESP_SUCCESS
        } else {
            byteArrayOf(0x6A.toByte(), 0x82.toByte())
        }
    }

    private fun isSelectCommand(command: ByteArray): Boolean =
        command.size >= 4 &&
            command[0] == 0x00.toByte() &&
            command[1] == 0xA4.toByte() &&
            command[2] == 0x04.toByte() &&
            command[3] == 0x00.toByte()

    private fun isGetResponseCommand(command: ByteArray): Boolean =
        command.size == 5 &&
            command[0] == 0x00.toByte() &&
            command[1] == 0xC0.toByte() &&
            command[2] == 0x00.toByte() &&
            command[3] == 0x00.toByte()

    private fun showNotRegisteredDialog() {
        vibrate()
        startActivity(
            Intent(this, NotRegisteredDialog::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            },
        )
    }

    private fun vibrate() {
        @Suppress("DEPRECATION")
        val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            vibrator.vibrate(
                VibrationEffect.createOneShot(50, VibrationEffect.DEFAULT_AMPLITUDE),
            )
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(50)
        }
    }

    private fun clearTransientState() {
        activeTransportSession = null
        pendingResponse = null
        pendingResponseOffset = 0
        resetIncomingRequest()
    }

    private fun resetIncomingRequest() {
        incomingInstruction = null
        incomingSequence = 0
        incomingPayload.reset()
    }

    companion object {
        private val AID = byteArrayOf(
            0xF0.toByte(),
            0x64.toByte(),
            0x65.toByte(),
            0x2E.toByte(),
            0x69.toByte(),
            0x6E.toByte(),
            0x66.toByte(),
            0x6F.toByte(),
            0x72.toByte(),
            0x6E.toByte(),
            0x61.toByte(),
            0x75.toByte(),
            0x74.toByte(),
            0x69.toByte(),
            0x6B.toByte(),
        )
        private val PROPRIETARY_CLASS: Byte = 0xD0.toByte()
        private const val INS_SESSION_INIT: Byte = 0x00
        private const val INS_REGISTRATION: Byte = 0x01
        private const val INS_AUTHENTICATION: Byte = 0x02
        private const val INS_USER_NOT_REGISTERED: Byte = 0x03
        private const val INS_REGISTRATION_ACK: Byte = 0x04
        private const val FLAG_FINAL = 0x00
        private const val FLAG_MORE = 0x80
        private const val MAX_INCOMING_PAYLOAD_BYTES = 16 * 1024
        private const val PURPOSE_REGISTRATION = "registration"
        private const val PURPOSE_AUTHENTICATION = "authentication"
        private const val PURPOSE_REGISTRATION_COMPLETE = "registration-complete"

        private val RESP_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
        private val RESP_UNKNOWN_COMMAND = byteArrayOf(0x6D.toByte(), 0x00.toByte())
        private val RESP_WRONG_LENGTH = byteArrayOf(0x67.toByte(), 0x00.toByte())
        private val RESP_INVALID_DATA = byteArrayOf(0x6A.toByte(), 0x80.toByte())
        private val RESP_CONDITIONS_NOT_SATISFIED =
            byteArrayOf(0x69.toByte(), 0x85.toByte())
        private val RESP_SECURITY_STATUS_NOT_SATISFIED =
            byteArrayOf(0x69.toByte(), 0x82.toByte())
        private val RESP_BIOMETRIC_REQUIRED = byteArrayOf(0x63.toByte(), 0x00.toByte())
        private val RESP_UNAUTHORIZED = byteArrayOf(0x69.toByte(), 0x83.toByte())
        private val RESP_ERROR = byteArrayOf(0x6F.toByte(), 0x00.toByte())
    }
}
