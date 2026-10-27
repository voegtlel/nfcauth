package de.infornautik.nfcauth

import android.app.AlertDialog
import android.os.Bundle
import android.util.Base64
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import org.json.JSONObject

class BiometricPromptActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pending = PendingAuthorizationStore.get() ?: return finish()
        val keyManager = KeyManager(this)
        val signature = try {
            keyManager.signatureForAuthentication(pending.serviceId, ServiceManifestParser.PROFILE_BIOMETRIC)
        } catch (_: Exception) {
            PendingAuthorizationStore.cancel()
            return finish()
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val approved = PendingAuthorizationStore.get() ?: return finish()
                    try {
                        val unsigned = JSONObject()
                            .put("protocol_version", 4)
                            .put("transaction_id", approved.request.getString("transaction_id"))
                            .put("request_hash", approved.requestHash)
                            .put("service_id", approved.serviceId)
                            .put("terminal_id", approved.terminalId)
                            .put("credential_id", approved.credentialId)
                            .put("assurance", approved.assurance)
                            .put("key_version", 1)
                            .put("approved_at", System.currentTimeMillis() / 1000L)
                        val payload = ASSERTION_DOMAIN.toByteArray() +
                            AuthorizationRequestVerifier.canonical(unsigned).toByteArray(Charsets.UTF_8)
                        val unlocked = result.cryptoObject?.signature ?: error("Biometric key was not unlocked")
                        unlocked.update(payload)
                        unsigned.put("signature", Base64.encodeToString(unlocked.sign(), Base64.NO_WRAP))
                        PendingAuthorizationStore.approve(approved.requestHash, unsigned)
                        AlertDialog.Builder(this@BiometricPromptActivity)
                            .setTitle("Authorization approved")
                            .setMessage("Tap the same terminal again to deliver the approval.")
                            .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
                            .setOnCancelListener { finish() }
                            .show()
                    } catch (_: Exception) {
                        PendingAuthorizationStore.cancel()
                        finish()
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    PendingAuthorizationStore.cancel()
                    finish()
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authorize ${pending.request.getString("action")}")
            .setSubtitle("${pending.request.getString("audience")} · 10 minute access")
            .setDescription(
                "Scopes: " + (0 until pending.request.getJSONArray("scopes").length())
                    .joinToString(", ") { pending.request.getJSONArray("scopes").getString(it) },
            )
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.dialog_button_cancel))
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    companion object {
        private const val ASSERTION_DOMAIN = "NFCAuth-v4-authorization-assertion\u0000"
    }
}
