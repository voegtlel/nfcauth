package de.infornautik.nfcauth

import android.content.Context
import android.util.Log
import android.util.Base64
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.KeyPair

class KeyManager(private val context: Context) {
    companion object {
        private const val TAG = "KeyManager"
        private const val KEY_ALIAS = "NFCAuthKey"
        private const val KEY_PROVIDER = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val KEY_SIZE = 256  // Standard EC key size
    }

    private val keyStore: KeyStore = KeyStore.getInstance(KEY_PROVIDER).apply {
        load(null)
    }

    init {
        if (!keyExists()) {
            generateAppKeyPair()
        }
    }

    private fun keyExists(): Boolean {
        return keyStore.containsAlias(KEY_ALIAS)
    }

    private fun generateAppKeyPair() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEY_PROVIDER
            )
            
            val parameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setKeySize(KEY_SIZE)
                setDigests(KeyProperties.DIGEST_SHA256)
                // Keys will be valid until manually deleted
                setUserAuthenticationRequired(false)
            }.build()

            keyPairGenerator.initialize(parameterSpec)
            keyPairGenerator.generateKeyPair()
            
            Log.d(TAG, "Generated and stored EC key pair in Android KeyStore")
        } catch (e: Exception) {
            Log.e(TAG, "Error generating EC key pair in KeyStore", e)
            throw e
        }
    }

    private fun getKeyPair(): KeyPair {
        try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
            val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
            return KeyPair(publicKey, privateKey)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting key pair from KeyStore", e)
            throw e
        }
    }

    fun sign(data: ByteArray): String {
        try {
            val privateKey = getKeyPair().private
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(data)
            return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Error signing data with app key", e)
            throw e
        }
    }

    fun getPublicKeyAsString(): String {
        return try {
            val publicKey = getKeyPair().public
            Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting public key as string", e)
            throw e
        }
    }
} 