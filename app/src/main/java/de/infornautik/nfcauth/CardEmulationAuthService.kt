package de.infornautik.nfcauth

import android.content.Context
import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.SystemClock
import android.os.VibrationEffect
import android.os.Vibrator
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

abstract class BaseCardEmulationAuthService : HostApduService() {
    protected abstract val authenticationProfile: String
    protected abstract val applicationId: ByteArray
    private lateinit var database: AuthDatabase
    private lateinit var keys: KeyManager
    private var session: NfcSessionCrypto? = null
    private var sessionContext: NfcSessionContext? = null
    private var sessionStartedAt = 0L
    private var pendingResponse: ByteArray? = null
    private var pendingOffset = 0
    private var incomingInstruction: Int? = null
    private var incomingSequence = 0
    private val incoming = ByteArrayOutputStream()

    override fun onCreate() {
        super.onCreate()
        database = AuthDatabase(this)
        keys = KeyManager(this)
    }

    override fun processCommandApdu(command: ByteArray?, extras: Bundle?): ByteArray {
        if (command == null) return WRONG_LENGTH
        return try {
            when {
                isSelect(command) -> processSelect(command)
                isGetResponse(command) -> processGetResponse(command)
                command.size < 5 -> WRONG_LENGTH
                command[0] != 0xD0.toByte() -> UNKNOWN_COMMAND
                command[1] == INS_SESSION_INIT -> processSessionInit(command)
                command[1] == INS_AUTHORIZATION -> processChunks(
                    command,
                    INS_AUTHORIZATION.toInt(),
                    PURPOSE_PROVISIONAL,
                    ::authorization,
                )
                command[1] == INS_ASSERTION_DELIVERY -> processChunks(
                    command,
                    INS_ASSERTION_DELIVERY.toInt(),
                    PURPOSE_PROVISIONAL,
                    ::assertionDelivery,
                )
                else -> UNKNOWN_COMMAND
            }
        } catch (_: Exception) {
            clearTransport()
            ERROR
        }
    }

    override fun onDeactivated(reason: Int) {
        // The transport session is gone, but a biometric authorization remains
        // process-local for the intentional second tap.
        clearTransport()
    }

    private fun authorization(raw: String): ByteArray {
        val active = session ?: return SECURITY_ERROR
        val context = sessionContext ?: return SECURITY_ERROR
        if (SystemClock.elapsedRealtime() - sessionStartedAt > SESSION_BIND_TIMEOUT_MS) return SECURITY_ERROR
        return try {
            val envelope = JSONObject(raw)
            val request = envelope.getJSONObject("request")
            val serviceOrigin = request.getString("service_origin")
            val serviceId = request.getString("service_id")
            val registration = database.getReaderInfo(serviceOrigin, serviceId, authenticationProfile)
                ?: return UNAUTHORIZED.also { showNotRegistered() }
            val verified = AuthorizationRequestVerifier.verifyAuthorization(
                envelope,
                context,
                registration,
                authenticationProfile,
            )
            active.authenticate(verified.payloadHash)
            val requestHash = verified.payloadHash.hex()
            if (authenticationProfile == ServiceManifestParser.PROFILE_BIOMETRIC) {
                PendingAuthorizationStore.put(
                    PendingAuthorization(
                        verified.request,
                        requestHash,
                        registration.serviceOrigin,
                        serviceId,
                        verified.request.getString("terminal_id"),
                        registration.credentialId,
                        authenticationProfile,
                        verified.request.getLong("expires_at"),
                    ),
                )
                requestBiometric()
                BIOMETRIC_REQUIRED
            } else {
                val assertion = createAssertion(verified.request, requestHash, registration)
                encryptedResponse(assertion.toString(), PURPOSE_ASSERTION)
            }
        } catch (_: Exception) {
            SECURITY_ERROR
        }
    }

    private fun assertionDelivery(raw: String): ByteArray {
        val active = session ?: return SECURITY_ERROR
        val context = sessionContext ?: return SECURITY_ERROR
        if (SystemClock.elapsedRealtime() - sessionStartedAt > SESSION_BIND_TIMEOUT_MS) return SECURITY_ERROR
        return try {
            val pending = PendingAuthorizationStore.get() ?: return CONDITIONS_ERROR
            val registration = database.getReaderInfo(
                pending.serviceOrigin,
                pending.serviceId,
                authenticationProfile,
            ) ?: return UNAUTHORIZED
            val envelope = JSONObject(raw)
            val verified = AuthorizationRequestVerifier.verifyDelivery(
                envelope,
                context,
                registration,
                authenticationProfile,
            )
            val delivery = verified.request
            require(delivery.getString("transaction_id") == pending.request.getString("transaction_id"))
            require(delivery.getString("request_hash") == pending.requestHash)
            require(delivery.getString("terminal_id") == pending.terminalId)
            active.authenticate(verified.payloadHash)
            val assertion = PendingAuthorizationStore.consume(
                delivery.getString("transaction_id"),
                delivery.getString("request_hash"),
                delivery.getString("terminal_id"),
            ) ?: return CONDITIONS_ERROR
            encryptedResponse(assertion.toString(), PURPOSE_ASSERTION_DELIVERY)
        } catch (_: Exception) {
            SECURITY_ERROR
        }
    }

    private fun createAssertion(request: JSONObject, requestHash: String, registration: ReaderInfo): JSONObject {
        val unsigned = JSONObject()
            .put("protocol_version", 4)
            .put("transaction_id", request.getString("transaction_id"))
            .put("request_hash", requestHash)
            .put("service_id", registration.serviceId)
            .put("terminal_id", request.getString("terminal_id"))
            .put("credential_id", registration.credentialId)
            .put("assurance", authenticationProfile)
            .put("key_version", 1)
            .put("approved_at", System.currentTimeMillis() / 1000L)
        val payload = ASSERTION_DOMAIN.toByteArray() +
            AuthorizationRequestVerifier.canonical(unsigned).toByteArray(Charsets.UTF_8)
        return unsigned.put(
            "signature",
            keys.sign(registration.serviceOrigin, registration.serviceId, authenticationProfile, payload),
        )
    }

    private fun processSessionInit(command: ByteArray): ByteArray {
        val length = command[4].toInt() and 0xff
        if (command[2] != 0.toByte() || command[3] != 0.toByte() || command.size != length + 5) {
            return WRONG_LENGTH
        }
        return try {
            val accepted = NfcSessionCrypto.accept(command.copyOfRange(5, command.size))
            session = accepted.session
            sessionContext = accepted.context
            sessionStartedAt = SystemClock.elapsedRealtime()
            setPendingResponse(accepted.response)
        } catch (_: Exception) {
            clearTransport()
            SECURITY_ERROR
        }
    }

    private fun processChunks(
        command: ByteArray,
        instruction: Int,
        purpose: String,
        complete: (String) -> ByteArray,
    ): ByteArray {
        val active = session ?: return SECURITY_ERROR
        val sequence = command[2].toInt() and 0xff
        val flags = command[3].toInt() and 0xff
        if (flags != 0 && flags != 0x80) return INVALID_DATA
        val length = command[4].toInt() and 0xff
        if (command.size != length + 5) return WRONG_LENGTH
        if (sequence == 0) {
            resetIncoming()
            incomingInstruction = instruction
        }
        if (incomingInstruction != instruction || sequence != incomingSequence) return INVALID_DATA
        if (incoming.size() + length > MAX_MESSAGE_SIZE) return WRONG_LENGTH
        incoming.write(command, 5, length)
        if (flags == 0x80) {
            incomingSequence += 1
            return SUCCESS
        }
        val encrypted = incoming.toByteArray()
        resetIncoming()
        val plaintext = try {
            active.decrypt(encrypted, purpose)
        } catch (_: Exception) {
            return SECURITY_ERROR
        }
        return try {
            complete(String(plaintext, Charsets.UTF_8))
        } finally {
            plaintext.fill(0)
        }
    }

    private fun encryptedResponse(value: String, purpose: String): ByteArray =
        setPendingResponse(session!!.encrypt(value.toByteArray(), purpose))

    private fun processGetResponse(command: ByteArray): ByteArray {
        val response = pendingResponse ?: return CONDITIONS_ERROR
        var requested = command[4].toInt() and 0xff
        if (requested == 0) requested = 256
        val length = minOf(requested, response.size - pendingOffset)
        if (length <= 0) return CONDITIONS_ERROR
        val result = ByteArray(length + 2)
        response.copyInto(result, 0, pendingOffset, pendingOffset + length)
        pendingOffset += length
        val remaining = response.size - pendingOffset
        if (remaining == 0) {
            result[length] = 0x90.toByte()
            result[length + 1] = 0
            pendingResponse = null
            pendingOffset = 0
        } else {
            result[length] = 0x61
            result[length + 1] = if (remaining >= 256) 0 else remaining.toByte()
        }
        return result
    }

    private fun setPendingResponse(value: ByteArray): ByteArray {
        pendingResponse = value
        pendingOffset = 0
        return if (value.size >= 256) byteArrayOf(0x61, 0) else byteArrayOf(0x61, value.size.toByte())
    }

    private fun processSelect(command: ByteArray): ByteArray {
        val length = command.getOrNull(4)?.toInt()?.and(0xff) ?: return WRONG_LENGTH
        val aid = command.copyOfRange(5, minOf(command.size, 5 + length))
        return if (aid.contentEquals(applicationId)) {
            clearTransport()
            vibrate()
            SUCCESS
        } else NOT_FOUND
    }

    private fun showNotRegistered() {
        runCatching {
            startActivity(Intent(this, NotRegisteredDialog::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    private fun requestBiometric() {
        vibrate()
        runCatching {
            startActivity(Intent(this, BiometricPromptActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    private fun vibrate() {
        @Suppress("DEPRECATION")
        val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            vibrator.vibrate(VibrationEffect.createOneShot(50, VibrationEffect.DEFAULT_AMPLITUDE))
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(50)
        }
    }

    private fun clearTransport() {
        session = null
        sessionContext = null
        pendingResponse = null
        pendingOffset = 0
        resetIncoming()
    }

    private fun resetIncoming() {
        incomingInstruction = null
        incomingSequence = 0
        incoming.reset()
    }

    private fun isSelect(value: ByteArray) = value.size >= 4 && value[0] == 0.toByte() &&
        value[1] == 0xA4.toByte() && value[2] == 4.toByte() && value[3] == 0.toByte()
    private fun isGetResponse(value: ByteArray) =
        value.size == 5 && value[0] == 0.toByte() && value[1] == 0xC0.toByte()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    companion object {
        private const val INS_SESSION_INIT: Byte = 0x00
        private const val INS_AUTHORIZATION: Byte = 0x08
        private const val INS_ASSERTION_DELIVERY: Byte = 0x09
        private const val PURPOSE_PROVISIONAL = "session-authentication"
        private const val PURPOSE_ASSERTION = "authorization-assertion"
        private const val PURPOSE_ASSERTION_DELIVERY = "assertion-delivery"
        private const val ASSERTION_DOMAIN = "NFCAuth-v4-authorization-assertion\u0000"
        private const val SESSION_BIND_TIMEOUT_MS = 15_000L
        private const val MAX_MESSAGE_SIZE = 64 * 1024
        private val SUCCESS = byteArrayOf(0x90.toByte(), 0)
        private val UNKNOWN_COMMAND = byteArrayOf(0x6D, 0)
        private val WRONG_LENGTH = byteArrayOf(0x67, 0)
        private val INVALID_DATA = byteArrayOf(0x6A, 0x80.toByte())
        private val CONDITIONS_ERROR = byteArrayOf(0x69, 0x85.toByte())
        private val SECURITY_ERROR = byteArrayOf(0x69, 0x82.toByte())
        private val UNAUTHORIZED = byteArrayOf(0x69, 0x83.toByte())
        private val BIOMETRIC_REQUIRED = byteArrayOf(0x63, 0)
        private val ERROR = byteArrayOf(0x6F, 0)
        private val NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())
    }
}

class PossessionCardEmulationAuthService : BaseCardEmulationAuthService() {
    override val authenticationProfile = ServiceManifestParser.PROFILE_POSSESSION
    override val applicationId = hex("F064652E696E666F726E617574696B01")
}

class BiometricCardEmulationAuthService : BaseCardEmulationAuthService() {
    override val authenticationProfile = ServiceManifestParser.PROFILE_BIOMETRIC
    override val applicationId = hex("F064652E696E666F726E617574696B02")
}

private fun hex(value: String) = ByteArray(value.length / 2) {
    value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
}
