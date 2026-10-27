package de.infornautik.nfcauth

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature

class KeyManager(@Suppress("UNUSED_PARAMETER") context: Context) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun ensureSigningKey(serviceOrigin: String, serviceId: String, profile: String) {
        val keyAlias = alias(serviceOrigin, serviceId, profile)
        if (keyStore.containsAlias(keyAlias)) return
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (profile == ServiceManifestParser.PROFILE_BIOMETRIC) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(builder.build())
            generateKeyPair()
        }
    }

    fun getPublicKeyAsString(serviceOrigin: String, serviceId: String, profile: String): String {
        ensureSigningKey(serviceOrigin, serviceId, profile)
        return Base64.encodeToString(
            keyStore.getCertificate(alias(serviceOrigin, serviceId, profile)).publicKey.encoded,
            Base64.NO_WRAP,
        )
    }

    fun signatureForAuthentication(serviceOrigin: String, serviceId: String, profile: String): Signature {
        ensureSigningKey(serviceOrigin, serviceId, profile)
        val privateKey = keyStore.getKey(alias(serviceOrigin, serviceId, profile), null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
    }

    fun sign(serviceOrigin: String, serviceId: String, profile: String, data: ByteArray): String {
        val signature = signatureForAuthentication(serviceOrigin, serviceId, profile)
        signature.update(data)
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    fun deleteServiceCredentials(serviceOrigin: String, serviceId: String, profile: String) {
        val keyAlias = alias(serviceOrigin, serviceId, profile)
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
    }

    private fun alias(serviceOrigin: String, serviceId: String, profile: String) =
        "NFCAuth-v4-" + profile + "-" + stable(serviceOrigin + "\u0000" + serviceId)

    private fun stable(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
