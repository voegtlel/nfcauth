package de.infornautik.nfcauth

import android.content.Context
import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.SystemClock
import android.os.VibrationEffect
import android.os.Vibrator
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream

abstract class BaseCardEmulationAuthService : HostApduService() {
    protected abstract val authenticationProfile: String
    protected abstract val applicationId: ByteArray
    private lateinit var database: AuthDatabase
    private lateinit var keys: KeyManager
    private lateinit var registration: RegistrationDataManager
    private val biometric = BiometricAuthStateManager.getInstance()
    private var session: NfcSessionCrypto? = null
    private var sessionContext: NfcSessionContext? = null
    private var sessionStartedAt = 0L
    private var verified: VerifiedServiceManifest? = null
    private var pendingResponse: ByteArray? = null
    private var pendingOffset = 0
    private var incomingInstruction: Int? = null
    private var incomingSequence = 0
    private val incoming = ByteArrayOutputStream()

    override fun onCreate() {
        super.onCreate()
        database = AuthDatabase(this)
        keys = KeyManager(this)
        registration = RegistrationDataManager(this)
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
                command[1] == INS_SESSION_AUTH ->
                    processChunks(command, INS_SESSION_AUTH.toInt(), PURPOSE_SESSION_AUTH, ::authenticateSession)
                verified == null -> SECURITY_ERROR
                command[1] == INS_REGISTRATION ->
                    processChunks(command, INS_REGISTRATION.toInt(), PURPOSE_REGISTRATION, ::registration)
                command[1] == INS_REGISTRATION_ACK ->
                    processChunks(command, INS_REGISTRATION_ACK.toInt(), PURPOSE_REGISTRATION_COMPLETE, ::registrationComplete)
                command[1] == INS_DISCOVERY ->
                    processChunks(command, INS_DISCOVERY.toInt(), PURPOSE_DISCOVERY, ::discovery)
                command[1] == INS_AUTHENTICATION ->
                    processChunks(command, INS_AUTHENTICATION.toInt(), PURPOSE_AUTHENTICATION, ::authentication)
                command[1] == INS_AUTHENTICATION_COMPLETE ->
                    processChunks(
                        command, INS_AUTHENTICATION_COMPLETE.toInt(),
                        PURPOSE_AUTHENTICATION_COMPLETE, ::authenticationComplete,
                    )
                else -> UNKNOWN_COMMAND
            }
        } catch (_: Exception) {
            resetIncoming()
            ERROR
        }
    }

    override fun onDeactivated(reason: Int) = clearTransient()

    private fun authenticateSession(raw: String): ByteArray {
        val context = sessionContext ?: return SECURITY_ERROR
        if (SystemClock.elapsedRealtime() - sessionStartedAt > SESSION_AUTH_TIMEOUT_MS) {
            clearTransient()
            return SECURITY_ERROR
        }
        return try {
            val authenticated = SessionCertificateVerifier.verify(JSONObject(raw), context, authenticationProfile)
            session!!.authenticate(authenticated.transcriptHash)
            verified = authenticated.service
            SUCCESS
        } catch (_: Exception) {
            clearTransient()
            SECURITY_ERROR
        }
    }

    private fun registration(raw: String): ByteArray {
        val service = verified ?: return SECURITY_ERROR
        return try {
            val offer = JSONObject(raw)
            require(offer.getInt("protocol_version") == 3)
            require(offer.getString("service_id") == service.manifest.serviceId)
            require(offer.getString("authentication_profile") == authenticationProfile)
            require(offer.getString("manifest_hash") == service.manifestHash)
            val credentialId = offer.getString("credential_id")
            val nonce = offer.getString("registration_nonce")
            require(credentialId.length in 16..255 && nonce.length == 64)
            registration.pendingResponseFor(
                service.manifest.serviceId, authenticationProfile, credentialId, nonce,
                service.manifestHash,
            )?.let {
                return encryptedResponse(it.toString(), PURPOSE_REGISTRATION)
            }
            if (registration.hasPendingRegistrationData()) return CONDITIONS_ERROR
            vibrate()
            startActivity(
                Intent(this, RegistrationActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    .putExtra(RegistrationActivity.EXTRA_MANIFEST, JSONObject(rawManifest(service.manifest)).toString())
                    .putExtra(RegistrationActivity.EXTRA_OFFER, offer.toString())
                    .putExtra(RegistrationActivity.EXTRA_CERTIFICATE_FINGERPRINT, service.certificateFingerprint)
                    .putExtra(RegistrationActivity.EXTRA_VERIFIED_DOMAIN, service.verifiedDomain),
            )
            SUCCESS
        } catch (_: Exception) {
            INVALID_DATA
        }
    }

    private fun registrationComplete(raw: String): ByteArray {
        val pending = registration.getPendingRegistrationData() ?: return CONDITIONS_ERROR
        val reader = registration.readerInfoFromPending(pending) ?: return INVALID_DATA
        if (reader.authenticationProfile != authenticationProfile) return SECURITY_ERROR
        val key = keys.pendingRegistrationKey(reader.serviceId, authenticationProfile) ?: return CONDITIONS_ERROR
        return try {
            NfcCrypto.decryptRegistrationAcknowledgement(
                JSONObject(raw), reader, pending.getString("registration_nonce"), key,
            )
            keys.commitRegistration(reader.serviceId, authenticationProfile)
            if (!database.registerReader(reader)) return ERROR
            registration.setPendingRegistrationData(null)
            vibrate()
            SUCCESS
        } catch (_: Exception) {
            SECURITY_ERROR
        } finally {
            key.fill(0)
        }
    }

    private fun discovery(raw: String): ByteArray {
        val current = verified ?: return SECURITY_ERROR
        return try {
            val request = JSONObject(raw)
            require(request.getInt("protocol_version") == 3)
            require(request.getString("service_id") == current.manifest.serviceId)
            require(request.getString("authentication_profile") == authenticationProfile)
            require(request.getString("manifest_hash") == current.manifestHash)
            val binding = session!!.discoveryBinding()
            require(request.getString("transport_binding") == binding)
            val reader = database.getReaderInfo(current.manifest.serviceId, authenticationProfile)
                ?: return UNAUTHORIZED.also { showNotRegistered() }
            // Any approved manifest or encryption identity change requires a new registration.
            require(reader.manifestHash == current.manifestHash)
            val state = keys.getState(reader.serviceId, authenticationProfile) ?: return UNAUTHORIZED
            val response = JSONObject()
                .put("protocol_version", 3)
                .put("service_id", reader.serviceId)
                .put("credential_id", reader.credentialId)
                .put("authentication_profile", authenticationProfile)
                .put("manifest_hash", current.manifestHash)
                .put("discovery_nonce", request.getString("discovery_nonce"))
                .put("transport_binding", binding)
                .put("key_epochs", JSONArray(state.availableEpochs()))
            encryptedResponse(response.toString(), PURPOSE_DISCOVERY)
        } catch (_: Exception) {
            SECURITY_ERROR
        }
    }

    private fun authentication(raw: String): ByteArray {
        return try {
            val envelope = JSONObject(raw)
            require(envelope.getString("authentication_profile") == authenticationProfile)
            val serviceId = envelope.getString("service_id")
            val reader = database.getReaderInfo(serviceId, authenticationProfile) ?: return UNAUTHORIZED
            val current = verified ?: return SECURITY_ERROR
            require(current.manifestHash == reader.manifestHash && current.manifest.serviceId == serviceId)
            val epoch = envelope.getInt("key_epoch")
            var state = keys.getState(serviceId, authenticationProfile) ?: return UNAUTHORIZED
            val key = state.keyForEpoch(epoch) ?: return SECURITY_ERROR
            val request = try {
                NfcCrypto.decryptAuthenticationRequest(envelope, reader, key, epoch)
            } finally {
                key.fill(0)
            }
            // A challenge encrypted under our pending epoch proves that the
            // service durably accepted the previous proof even if KEY_COMMIT
            // was lost. Promote it now while retaining the old epoch.
            val pendingRotationId = state.rotationId
            if (state.pendingEpoch == epoch && pendingRotationId != null) {
                state = keys.promoteRotation(serviceId, authenticationProfile, pendingRotationId)
            }
            val binding = session!!.discoveryBinding()
            require(
                request.getInt("protocol_version") == 3 &&
                    request.getString("service_id") == serviceId &&
                    request.getString("credential_id") == reader.credentialId &&
                    request.getString("authentication_profile") == authenticationProfile &&
                    request.getInt("key_epoch") == epoch &&
                    request.getString("transport_binding") == binding &&
                    request.getString("manifest_hash") == reader.manifestHash,
            )
            if (authenticationProfile == ServiceManifestParser.PROFILE_BIOMETRIC && !biometric.isAuthenticated()) {
                requestBiometric()
                return BIOMETRIC_REQUIRED
            }
            val nonce = request.getString("nonce")
            val signature = keys.sign(
                serviceId, authenticationProfile,
                NfcCrypto.authenticationSignaturePayload(reader, epoch, nonce, binding),
            )
            val currentKey = state.keyForEpoch(epoch) ?: return SECURITY_ERROR
            val nextKey = NfcCrypto.deriveRotatedKey(reader, currentKey, epoch, nonce)
            currentKey.fill(0)
            keys.prepareRotation(serviceId, authenticationProfile, epoch, nextKey, nonce)
            nextKey.fill(0)
            val response = JSONObject()
                .put("protocol_version", 3)
                .put("service_id", serviceId)
                .put("credential_id", reader.credentialId)
                .put("authentication_profile", authenticationProfile)
                .put("key_epoch", epoch)
                .put("nonce", nonce)
                .put("transport_binding", binding)
                .put("manifest_hash", reader.manifestHash)
                .put("signature", signature)
            val responseKey = state.keyForEpoch(epoch) ?: return SECURITY_ERROR
            try {
                encryptedResponse(
                    NfcCrypto.encryptAuthenticationResponse(reader, responseKey, epoch, response).toString(),
                    PURPOSE_AUTHENTICATION,
                )
            } finally {
                responseKey.fill(0)
            }
        } catch (_: android.security.keystore.UserNotAuthenticatedException) {
            requestBiometric()
            BIOMETRIC_REQUIRED
        } catch (_: Exception) {
            SECURITY_ERROR
        }
    }

    private fun authenticationComplete(raw: String): ByteArray {
        return try {
            val envelope = JSONObject(raw)
            require(envelope.getString("authentication_profile") == authenticationProfile)
            val serviceId = envelope.getString("service_id")
            val reader = database.getReaderInfo(serviceId, authenticationProfile) ?: return UNAUTHORIZED
            val epoch = envelope.getInt("key_epoch")
            val state = keys.getState(serviceId, authenticationProfile) ?: return UNAUTHORIZED
            val key = state.keyForEpoch(epoch) ?: return SECURITY_ERROR
            val commit = NfcCrypto.decryptKeyCommit(envelope, reader, key, epoch)
            require(commit.getString("status") == "authentication-succeeded")
            val rotationId = commit.getString("rotation_id")
            require(state.pendingEpoch == epoch && state.rotationId == rotationId)
            val promoted = keys.promoteRotation(serviceId, authenticationProfile, rotationId)
            val active = promoted.activeKey
            val response = NfcCrypto.encryptKeyCommitAck(reader, active, promoted.activeEpoch, rotationId)
            active.fill(0)
            vibrate()
            encryptedResponse(response.toString(), PURPOSE_AUTHENTICATION_COMPLETE)
        } catch (_: Exception) {
            SECURITY_ERROR
        }
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
            verified = null
            setPendingResponse(accepted.response)
        } catch (_: Exception) {
            clearTransient()
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
        if (incoming.size() + length > 64 * 1024) return WRONG_LENGTH
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
            clearTransient()
            vibrate()
            SUCCESS
        } else NOT_FOUND
    }

    private fun rawManifest(value: ServiceManifest) = JSONObject()
        .put("service_origin", value.serviceOrigin).put("service_id", value.serviceId)
        .put("service_name", value.serviceName).put("operator_name", value.operatorName)
        .put("privacy_policy_url", value.privacyPolicyUrl)
        .put("privacy_notice_version", value.privacyNoticeVersion)
        .put("requested_fields", JSONArray(value.requestedFields)).put("purposes", JSONObject(value.purposes))
        .put("data_deletion_url_or_contact", value.deletionUrlOrContact)
        .put("authentication_profile", value.authenticationProfile)
        .put("encryption_public_key", value.encryptionPublicKey)
        .put("privacy_notice_material_change", value.privacyNoticeMaterialChange).toString()

    private fun showNotRegistered() {
        startActivity(Intent(this, NotRegisteredDialog::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
    private fun requestBiometric() {
        vibrate()
        startActivity(Intent(this, BiometricPromptActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
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
    private fun clearTransient() {
        session = null
        sessionContext = null
        verified = null
        pendingResponse = null
        pendingOffset = 0
        resetIncoming()
    }
    private fun resetIncoming() {
        incomingInstruction = null
        incomingSequence = 0
        incoming.reset()
    }
    private fun isSelect(value: ByteArray) =
        value.size >= 4 && value[0] == 0.toByte() && value[1] == 0xA4.toByte() &&
            value[2] == 4.toByte() && value[3] == 0.toByte()
    private fun isGetResponse(value: ByteArray) =
        value.size == 5 && value[0] == 0.toByte() && value[1] == 0xC0.toByte()

    companion object {
        private const val INS_SESSION_INIT: Byte = 0x00
        private const val INS_REGISTRATION: Byte = 0x01
        private const val INS_AUTHENTICATION: Byte = 0x02
        private const val INS_REGISTRATION_ACK: Byte = 0x04
        private const val INS_DISCOVERY: Byte = 0x05
        private const val INS_SESSION_AUTH: Byte = 0x06
        private const val INS_AUTHENTICATION_COMPLETE: Byte = 0x07
        private const val PURPOSE_SESSION_AUTH = "session-authentication"
        private const val PURPOSE_REGISTRATION = "registration"
        private const val PURPOSE_AUTHENTICATION = "authentication"
        private const val PURPOSE_REGISTRATION_COMPLETE = "registration-complete"
        private const val PURPOSE_DISCOVERY = "credential-discovery"
        private const val PURPOSE_AUTHENTICATION_COMPLETE = "authentication-complete"
        private const val SESSION_AUTH_TIMEOUT_MS = 5_000L
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
