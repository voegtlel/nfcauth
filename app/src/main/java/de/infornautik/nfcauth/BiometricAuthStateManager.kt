package de.infornautik.nfcauth

import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class BiometricAuthStateManager private constructor() {
    companion object {
        private const val TAG = "BiometricAuthStateManager"
        private const val AUTH_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes

        @Volatile
        private var instance: BiometricAuthStateManager? = null

        fun getInstance(): BiometricAuthStateManager {
            return instance ?: synchronized(this) {
                instance ?: BiometricAuthStateManager().also { instance = it }
            }
        }
    }

    private val isAuthenticated = AtomicBoolean(false)
    private val lastAuthTime = AtomicLong(0)
    private val authType = AtomicLong(0)

    fun setAuthenticated(type: Int) {
        isAuthenticated.set(true)
        lastAuthTime.set(System.currentTimeMillis())
        authType.set(type.toLong())
        Log.d(TAG, "Authentication state set to true with type: $type")
    }

    fun clearAuthentication() {
        isAuthenticated.set(false)
        lastAuthTime.set(0)
        authType.set(0)
        Log.d(TAG, "Authentication state cleared")
    }

    fun isAuthenticated(): Boolean {
        val currentTime = System.currentTimeMillis()
        val lastAuth = lastAuthTime.get()
        
        // Check if authentication has expired
        if (currentTime - lastAuth > AUTH_TIMEOUT_MS) {
            clearAuthentication()
            return false
        }
        
        return isAuthenticated.get()
    }

    fun getAuthType(): Int {
        return authType.get().toInt()
    }

    fun getLastAuthTime(): Long {
        return lastAuthTime.get()
    }
} 