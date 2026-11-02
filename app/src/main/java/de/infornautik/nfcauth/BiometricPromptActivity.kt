package de.infornautik.nfcauth

import android.app.AlertDialog
import android.content.pm.ApplicationInfo
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
        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0 &&
            intent.getBooleanExtra(EXTRA_PREVIEW_APPROVAL, false)
        ) {
            showApprovedNotice()
            return
        }
        val pending = PendingAuthorizationStore.get() ?: return finish()
        val keyManager = KeyManager(this)
        val signature = try {
            keyManager.signatureForAuthentication(
                pending.serviceOrigin,
                pending.serviceId,
                ServiceManifestParser.PROFILE_BIOMETRIC,
            )
        } catch (_: Exception) {
            PendingAuthorizationStore.cancel(pending.requestHash)
            return finish()
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val approved = pending
                    if (PendingAuthorizationStore.get()?.requestHash != approved.requestHash) return finish()
                    try {
                        val unsigned = JSONObject()
                            .put("protocol_version", 4)
                            .put("transaction_id", approved.request.getString("transaction_id"))
                            .put("request_hash", approved.requestHash)
                            .put("service_id", approved.serviceId)
                            .put("terminal_id", approved.terminalId)
                            .put("credential_id", approved.credentialId)
                            .put("assurance", approved.assurance)
                            .put("approved_at", System.currentTimeMillis() / 1000L)
                        val payload = ASSERTION_DOMAIN.toByteArray() +
                            AuthorizationRequestVerifier.canonical(unsigned).toByteArray(Charsets.UTF_8)
                        val unlocked = result.cryptoObject?.signature ?: error("Biometric key was not unlocked")
                        unlocked.update(payload)
                        unsigned.put("signature", Base64.encodeToString(unlocked.sign(), Base64.NO_WRAP))
                        PendingAuthorizationStore.approve(approved.requestHash, unsigned)
                        showApprovedNotice()
                    } catch (_: Exception) {
                        PendingAuthorizationStore.cancel(pending.requestHash)
                        finish()
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    PendingAuthorizationStore.cancel(pending.requestHash)
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

    private fun showApprovedNotice() {
        AlertDialog.Builder(this)
            .setTitle("Authorization approved")
            .setMessage("Tap the same terminal again to finish signing in.")
            .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
            .setOnCancelListener { finish() }
            .show()
    }

    companion object {
        const val EXTRA_PREVIEW_APPROVAL = "preview_authorization_approved"
        private const val ASSERTION_DOMAIN = "NFCAuth-v4-authorization-assertion\u0000"
    }
}
