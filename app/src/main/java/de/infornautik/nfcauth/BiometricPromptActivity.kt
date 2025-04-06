package de.infornautik.nfcauth

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContracts
import android.app.AlertDialog
import android.os.Handler
import android.os.Looper

class BiometricPromptActivity : AppCompatActivity() {
    companion object {
        private const val TAG = "BiometricPromptActivity"
    }

    private var biometricPrompt: BiometricPrompt? = null
    private val authStateManager = BiometricAuthStateManager.getInstance()
    private val handler = Handler(Looper.getMainLooper())

    private val deviceUnlockLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            Log.d(TAG, "Device unlocked successfully")
            showInfoDialog()
            showBiometricPrompt()
        } else {
            Log.e(TAG, "Device unlock failed")
            authStateManager.clearAuthentication()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d(TAG, "BiometricPromptActivity onCreate")

        // First try to unlock the device
        requestDeviceUnlock()
    }

    private fun showInfoDialog() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.hold_device_title))
            .setMessage(getString(R.string.hold_device_message))
            .setPositiveButton(getString(R.string.dialog_button_ok)) { dialog, _ ->
                dialog.dismiss()
                // Show biometric prompt after a short delay
                handler.postDelayed({
                    showBiometricPrompt()
                }, 500)
            }
            .setCancelable(false)
            .show()
    }

    private fun requestDeviceUnlock() {
        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (keyguardManager.isKeyguardLocked) {
            Log.d(TAG, "Device is locked, requesting unlock")
            @Suppress("DEPRECATION")
            val intent = keyguardManager.createConfirmDeviceCredentialIntent(
                getString(R.string.unlock_device_title),
                getString(R.string.unlock_device_message)
            )
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            deviceUnlockLauncher.launch(intent)
        } else {
            Log.d(TAG, "Device is already unlocked, showing info dialog")
            showInfoDialog()
        }
    }

    private fun showBiometricPrompt() {
        // Initialize biometric prompt
        val executor: Executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.d(TAG, "Biometric authentication succeeded")
                    authStateManager.setAuthenticated(result.authenticationType)
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.e(TAG, "Biometric authentication error: $errString")
                    authStateManager.clearAuthentication()
                    finish()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Log.e(TAG, "Biometric authentication failed")
                    authStateManager.clearAuthentication()
                    finish()
                }
            })

        // Show the biometric prompt
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_prompt_title))
            .setSubtitle(getString(R.string.biometric_prompt_subtitle))
            .setNegativeButtonText(getString(R.string.dialog_button_cancel))
            .build()

        biometricPrompt?.authenticate(promptInfo)
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "BiometricPromptActivity onDestroy")
    }
} 