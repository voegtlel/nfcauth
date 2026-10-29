package de.infornautik.nfcauth

import android.app.AlertDialog
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.net.URL
import java.security.cert.X509Certificate
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class RenewalActivity : AppCompatActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var database: AuthDatabase
    private lateinit var keys: KeyManager
    private var registration: ReaderInfo? = null
    private var verifiedManifest: VerifiedServiceManifest? = null
    private var renewal: JSONObject? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        database = AuthDatabase(this)
        keys = KeyManager(this)
        val origin = intent.getStringExtra(EXTRA_ORIGIN) ?: return fail("Registration origin is missing")
        val serviceId = intent.getStringExtra(EXTRA_SERVICE_ID) ?: return fail("Service ID is missing")
        val profile = intent.getStringExtra(EXTRA_PROFILE) ?: return fail("Credential profile is missing")
        registration = database.getReaderInfo(origin, serviceId, profile)
            ?: return fail("Registration is no longer available")
        fetchCurrentProviderMetadata()
    }

    private fun fetchCurrentProviderMetadata() {
        val current = registration ?: return fail("Registration is no longer available")
        executor.execute {
            try {
                val connection = URL("${current.serviceOrigin}/.well-known/nfc-authenticator")
                    .openConnection() as HttpsURLConnection
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.instanceFollowRedirects = false
                connection.requestMethod = "GET"
                require(connection.responseCode == 200)
                val certificate = connection.serverCertificates.first() as X509Certificate
                val envelope = JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
                require(envelope.toString().toByteArray().size <= 64 * 1024)
                val signed = ProviderManifestVerifier.verify(envelope, current.serviceOrigin, certificate)
                val document = signed.manifest
                val manifest = ServiceManifestParser.parse(document)
                require(manifest.serviceOrigin == current.serviceOrigin && manifest.serviceId == current.serviceId)
                require(ServiceManifestParser.hash(document) == current.manifestHash) {
                    "Provider disclosure changed; a new registration confirmation is required"
                }
                checkPolicy(manifest.privacyPolicyUrl)
                val verified = VerifiedServiceManifest(
                    manifest,
                    current.manifestHash,
                    ServiceManifestParser.fingerprint(ServiceManifestParser.parseEncryptionKey(manifest.encryptionPublicKey)),
                    signed.certificateFingerprint,
                    signed.verifiedDomain,
                )
                require(verified.encryptionKeyFingerprint == current.encryptionKeyFingerprint)
                verifiedManifest = verified
                startRenewal()
            } catch (_: Exception) {
                runOnUiThread {
                    fail("Provider identity or disclosure changed. Review the provider and register again.")
                }
            }
        }
    }

    private fun startRenewal() {
        val current = registration ?: return fail("Registration is no longer available")
        val manifest = verifiedManifest?.manifest ?: return fail("Provider identity could not be verified")
        try {
            val response = postJson(
                manifest.renewalEndpoint,
                JSONObject().put("credential_id", current.credentialId),
            )
            val challenge = response.getJSONObject("renewal")
            validateChallenge(challenge, current, manifest)
            renewal = challenge
            runOnUiThread { showRenewalConfirmation(challenge, current) }
        } catch (_: Exception) {
            runOnUiThread { fail("Registration renewal could not be started") }
        }
    }

    private fun validateChallenge(value: JSONObject, current: ReaderInfo, manifest: ServiceManifest) {
        val now = System.currentTimeMillis() / 1000L
        require(value.getInt("protocol_version") == ServiceManifestParser.PROTOCOL_VERSION)
        require(value.getString("action") == "registration.renew")
        require(value.getString("credential_id") == current.credentialId)
        require(value.getString("service_id") == current.serviceId)
        require(value.getString("profile") == current.authenticationProfile)
        require(value.getString("challenge").length >= 32)
        require(value.getLong("issued_at") <= now + 30)
        require(value.getLong("challenge_expires_at") > now)
        require(value.getLong("challenge_expires_at") - value.getLong("issued_at") <= 120)
        val proposed = value.getLong("proposed_registration_expires_at")
        require(proposed > now)
        require(proposed - now <= (manifest.registrationLifetimeDays + 1L) * 86_400L)
    }

    private fun showRenewalConfirmation(value: JSONObject, current: ReaderInfo) {
        val proposed = DateFormat.getDateInstance().format(
            Date(value.getLong("proposed_registration_expires_at") * 1000L),
        )
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.renew_registration_title, current.serviceName))
            .setMessage(getString(R.string.renew_registration_message, current.operatorName, proposed))
            .setNegativeButton(R.string.dialog_button_cancel) { _, _ -> finish() }
            .setPositiveButton(R.string.renew_registration_action) { _, _ -> authorizeRenewal() }
            .setOnCancelListener { finish() }
            .show()
    }

    private fun authorizeRenewal() {
        val current = registration ?: return fail("Registration is no longer available")
        val challenge = renewal ?: return fail("Renewal challenge is unavailable")
        val payload = RENEWAL_DOMAIN.toByteArray(Charsets.UTF_8) +
            AuthorizationRequestVerifier.canonical(challenge).toByteArray(Charsets.UTF_8)
        if (current.authenticationProfile == ServiceManifestParser.PROFILE_BIOMETRIC) {
            biometricProof(current, payload)
        } else {
            completeRenewal(keys.sign(current.serviceOrigin, current.serviceId, current.authenticationProfile, payload))
        }
    }

    private fun biometricProof(current: ReaderInfo, payload: ByteArray) {
        val signature = keys.signatureForAuthentication(
            current.serviceOrigin,
            current.serviceId,
            current.authenticationProfile,
        )
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val unlocked = result.cryptoObject?.signature ?: error("Credential key was not unlocked")
                        unlocked.update(payload)
                        completeRenewal(Base64.encodeToString(unlocked.sign(), Base64.NO_WRAP))
                    } catch (_: Exception) {
                        fail("Registration renewal proof failed")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    fail("Registration renewal was cancelled")
                }
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.renew_registration_title, current.serviceName))
                .setSubtitle(getString(R.string.renew_registration_biometric_subtitle))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText(getString(R.string.dialog_button_cancel))
                .build(),
            BiometricPrompt.CryptoObject(signature),
        )
    }

    private fun completeRenewal(signature: String) {
        val current = registration ?: return fail("Registration is no longer available")
        val manifest = verifiedManifest ?: return fail("Provider identity could not be verified")
        val renewalId = renewal?.getString("renewal_id") ?: return fail("Renewal ID is missing")
        executor.execute {
            try {
                val response = postJson(
                    manifest.manifest.renewalEndpoint.trimEnd('/') + "/$renewalId/complete",
                    JSONObject().put("signature", signature),
                )
                require(response.getString("credential_id") == current.credentialId)
                val expiresAt = response.getLong("registration_expires_at") * 1000L
                require(expiresAt == renewal?.getLong("proposed_registration_expires_at")?.times(1000L))
                require(
                    database.updateRegistrationExpiration(
                        current.serviceOrigin,
                        current.serviceId,
                        current.authenticationProfile,
                        expiresAt,
                        manifest.certificateFingerprint,
                        manifest.verifiedDomain,
                    ),
                )
                runOnUiThread {
                    Toast.makeText(this, R.string.renew_registration_success, Toast.LENGTH_LONG).show()
                    finish()
                }
            } catch (_: Exception) {
                runOnUiThread { fail("Registration renewal failed") }
            }
        }
    }

    private fun checkPolicy(url: String) {
        val connection = URL(url).openConnection() as HttpsURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.instanceFollowRedirects = true
        connection.requestMethod = "GET"
        require(connection.responseCode in 200..399 && connection.url.protocol == "https")
        connection.inputStream.use { input ->
            val buffer = ByteArray(1024)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                total += read
                require(total <= 1024 * 1024)
            }
        }
    }

    private fun postJson(url: String, body: JSONObject): JSONObject {
        val connection = URL(url).openConnection() as HttpsURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.instanceFollowRedirects = false
        connection.requestMethod = "POST"
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("Accept", "application/json")
        connection.doOutput = true
        connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        require(connection.responseCode in 200..299)
        return JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
    }

    private fun fail(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    override fun onDestroy() {
        executor.shutdownNow()
        database.close()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_ORIGIN = "provider_origin"
        const val EXTRA_SERVICE_ID = "service_id"
        const val EXTRA_PROFILE = "authentication_profile"
        private const val RENEWAL_DOMAIN = "NFCAuth-v4-registration-renewal\u0000"
    }
}
