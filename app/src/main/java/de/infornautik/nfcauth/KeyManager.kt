package de.infornautik.nfcauth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature

class KeyManager(context: Context) {
    companion object {
        private const val KEY_PROVIDER = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val SERVICE_KEY_PREFIX = "NFCAuthServiceSigning-"
        private const val LEGACY_GLOBAL_KEY_ALIAS = "NFCAuthKey"
        private const val ACTIVE_SESSION_PREFIX = "active-session-"
        private const val PENDING_SESSION_PREFIX = "pending-session-"
    }

    private val keyStore = KeyStore.getInstance(KEY_PROVIDER).apply { load(null) }
    private val preferences = EncryptedSharedPreferences.create(
        context,
        "service_secrets",
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    init {
        // Version 1 used one key for every reader. Keeping it would allow
        // cross-service correlation, so it is intentionally retired.
        if (keyStore.containsAlias(LEGACY_GLOBAL_KEY_ALIAS)) {
            keyStore.deleteEntry(LEGACY_GLOBAL_KEY_ALIAS)
        }
    }

    fun getPublicKeyAsString(serviceId: String): String {
        ensureSigningKey(serviceId)
        val certificate = keyStore.getCertificate(signingAlias(serviceId))
            ?: throw IllegalStateException("Service signing key is unavailable")
        return Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)
    }

    fun sign(serviceId: String, data: ByteArray): String {
        ensureSigningKey(serviceId)
        val privateKey = keyStore.getKey(signingAlias(serviceId), null) as? PrivateKey
            ?: throw IllegalStateException("Service signing key is unavailable")
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(data)
            Base64.encodeToString(sign(), Base64.NO_WRAP)
        }
    }

    fun savePendingSessionKey(serviceId: String, key: ByteArray) {
        preferences.edit()
            .putString(pendingSessionPreference(serviceId), Base64.encodeToString(key, Base64.NO_WRAP))
            .apply()
    }

    fun getPendingSessionKey(serviceId: String): ByteArray? =
        preferences.getString(pendingSessionPreference(serviceId), null)
            ?.let { Base64.decode(it, Base64.NO_WRAP) }

    fun commitPendingSessionKey(serviceId: String) {
        val encoded = preferences.getString(pendingSessionPreference(serviceId), null)
            ?: throw IllegalStateException("Pending service secret is unavailable")
        preferences.edit()
            .putString(activeSessionPreference(serviceId), encoded)
            .remove(pendingSessionPreference(serviceId))
            .commit()
    }

    fun getSessionKey(serviceId: String): ByteArray? =
        preferences.getString(activeSessionPreference(serviceId), null)
            ?.let { Base64.decode(it, Base64.NO_WRAP) }

    fun discardPendingSessionKey(serviceId: String, deleteSigningKey: Boolean) {
        preferences.edit().remove(pendingSessionPreference(serviceId)).apply()
        if (deleteSigningKey) {
            deleteSigningKey(serviceId)
        }
    }

    fun deleteServiceCredentials(serviceId: String) {
        preferences.edit()
            .remove(activeSessionPreference(serviceId))
            .remove(pendingSessionPreference(serviceId))
            .commit()
        deleteSigningKey(serviceId)
    }

    private fun ensureSigningKey(serviceId: String) {
        val alias = signingAlias(serviceId)
        if (keyStore.containsAlias(alias)) return

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEY_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun deleteSigningKey(serviceId: String) {
        val alias = signingAlias(serviceId)
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    private fun signingAlias(serviceId: String) = SERVICE_KEY_PREFIX + stableId(serviceId)
    private fun activeSessionPreference(serviceId: String) = ACTIVE_SESSION_PREFIX + stableId(serviceId)
    private fun pendingSessionPreference(serviceId: String) = PENDING_SESSION_PREFIX + stableId(serviceId)

    private fun stableId(serviceId: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(serviceId.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
