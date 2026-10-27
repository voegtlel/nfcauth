package de.infornautik.nfcauth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature

data class CredentialKeyState(
    val activeKey: ByteArray,
    val activeEpoch: Int,
    val previousKey: ByteArray?,
    val previousEpoch: Int?,
    val pendingKey: ByteArray?,
    val pendingEpoch: Int?,
    val rotationId: String?,
) {
    fun keyForEpoch(epoch: Int): ByteArray? = when (epoch) {
        activeEpoch -> activeKey.copyOf()
        previousEpoch -> previousKey?.copyOf()
        pendingEpoch -> pendingKey?.copyOf()
        else -> null
    }
    fun availableEpochs() = listOfNotNull(activeEpoch, previousEpoch, pendingEpoch).distinct().sortedDescending()
}

class KeyManager(context: Context) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val preferences = EncryptedSharedPreferences.create(
        context, "service-secrets-v3",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun getPublicKeyAsString(serviceId: String, profile: String): String {
        ensureSigningKey(serviceId, profile)
        return Base64.encodeToString(
            keyStore.getCertificate(alias(serviceId, profile)).publicKey.encoded, Base64.NO_WRAP,
        )
    }

    fun sign(serviceId: String, profile: String, data: ByteArray): String {
        ensureSigningKey(serviceId, profile)
        val privateKey = keyStore.getKey(alias(serviceId, profile), null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            Base64.encodeToString(sign(), Base64.NO_WRAP)
        }
    }

    fun savePendingRegistration(serviceId: String, profile: String, key: ByteArray) {
        save(serviceId, profile, JSONObject().put("pending", encode(key)).put("pending_epoch", 0))
    }

    fun pendingRegistrationKey(serviceId: String, profile: String) =
        loadJson(serviceId, profile)?.optString("pending")?.takeIf(String::isNotBlank)?.let(::decode)

    fun commitRegistration(serviceId: String, profile: String) {
        val pending = pendingRegistrationKey(serviceId, profile) ?: error("Registration key is unavailable")
        save(serviceId, profile, JSONObject().put("active", encode(pending)).put("active_epoch", 0))
        pending.fill(0)
    }

    fun getState(serviceId: String, profile: String): CredentialKeyState? {
        val value = loadJson(serviceId, profile) ?: return null
        val active = value.optString("active").takeIf(String::isNotBlank) ?: return null
        return CredentialKeyState(
            decode(active), value.getInt("active_epoch"),
            value.optString("previous").takeIf(String::isNotBlank)?.let(::decode),
            if (value.has("previous_epoch") && !value.isNull("previous_epoch")) value.getInt("previous_epoch") else null,
            value.optString("pending").takeIf(String::isNotBlank)?.let(::decode),
            if (value.has("pending_epoch") && !value.isNull("pending_epoch")) value.getInt("pending_epoch") else null,
            value.optString("rotation_id").takeIf(String::isNotBlank),
        )
    }

    fun prepareRotation(
        serviceId: String, profile: String, expectedEpoch: Int, newKey: ByteArray, rotationId: String,
    ) {
        val state = getState(serviceId, profile) ?: error("Credential key is unavailable")
        if (state.pendingEpoch == expectedEpoch + 1 && state.rotationId == rotationId) return
        require(state.activeEpoch == expectedEpoch)
        save(
            serviceId, profile,
            JSONObject()
                .put("active", encode(state.activeKey)).put("active_epoch", state.activeEpoch)
                .put("previous", state.previousKey?.let(::encode)).put("previous_epoch", state.previousEpoch)
                .put("pending", encode(newKey)).put("pending_epoch", expectedEpoch + 1)
                .put("rotation_id", rotationId),
        )
        state.activeKey.fill(0)
        state.previousKey?.fill(0)
    }

    fun promoteRotation(serviceId: String, profile: String, rotationId: String): CredentialKeyState {
        val state = getState(serviceId, profile) ?: error("Credential key is unavailable")
        require(state.rotationId == rotationId && state.pendingKey != null && state.pendingEpoch != null)
        save(
            serviceId, profile,
            JSONObject()
                .put("active", encode(state.pendingKey)).put("active_epoch", state.pendingEpoch)
                .put("previous", encode(state.activeKey)).put("previous_epoch", state.activeEpoch),
        )
        return getState(serviceId, profile)!!
    }

    fun discardPendingRegistration(serviceId: String, profile: String, deleteSigningKey: Boolean) {
        preferences.edit().remove(pref(serviceId, profile)).commit()
        if (deleteSigningKey) deleteSigningKey(serviceId, profile)
    }

    fun deleteServiceCredentials(serviceId: String, profile: String) {
        preferences.edit().remove(pref(serviceId, profile)).commit()
        deleteSigningKey(serviceId, profile)
    }

    private fun ensureSigningKey(serviceId: String, profile: String) {
        val keyAlias = alias(serviceId, profile)
        if (keyStore.containsAlias(keyAlias)) return
        val spec = KeyGenParameterSpec.Builder(
            keyAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(256).setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(profile == ServiceManifestParser.PROFILE_BIOMETRIC)
            .apply {
                if (profile == ServiceManifestParser.PROFILE_BIOMETRIC) {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(15)
                }
            }.build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun deleteSigningKey(serviceId: String, profile: String) {
        val keyAlias = alias(serviceId, profile)
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
    }
    private fun save(serviceId: String, profile: String, value: JSONObject) {
        check(preferences.edit().putString(pref(serviceId, profile), value.toString()).commit())
    }
    private fun loadJson(serviceId: String, profile: String) =
        preferences.getString(pref(serviceId, profile), null)?.let(::JSONObject)
    private fun alias(serviceId: String, profile: String) =
        "NFCAuth-v3-" + profile + "-" + stable(serviceId)
    private fun pref(serviceId: String, profile: String) =
        "credential-" + profile + "-" + stable(serviceId)
    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String) = Base64.decode(value, Base64.NO_WRAP)
    private fun stable(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
