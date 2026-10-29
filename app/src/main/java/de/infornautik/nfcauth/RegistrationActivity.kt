package de.infornautik.nfcauth

import android.app.AlertDialog
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class RegistrationActivity : AppCompatActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var keys: KeyManager
    private lateinit var database: AuthDatabase
    private var verified: VerifiedServiceManifest?
        get() = PendingRegistrationSession.verified
        set(value) { PendingRegistrationSession.verified = value }
    private var manifestDocument: JSONObject?
        get() = PendingRegistrationSession.manifestDocument
        set(value) { PendingRegistrationSession.manifestDocument = value }
    private var selectedProfile: String?
        get() = PendingRegistrationSession.selectedProfile
        set(value) { PendingRegistrationSession.selectedProfile = value }
    private var registrationId: String?
        get() = PendingRegistrationSession.registrationId
        set(value) { PendingRegistrationSession.registrationId = value }
    private var completionCode: String?
        get() = PendingRegistrationSession.completionCode
        set(value) { PendingRegistrationSession.completionCode = value }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keys = KeyManager(this)
        database = AuthDatabase(this)
        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            intent.getStringExtra(EXTRA_PREVIEW_MANIFEST)?.let {
                showPreviewManifest(it)
                return
            }
        }
        if (intent.data?.scheme == CALLBACK_SCHEME) {
            handleCallback(intent.data!!)
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN) ?: return fail("Provider URL is missing")
            fetchProvider(origin)
        }
    }

    private fun showPreviewManifest(raw: String) {
        try {
            val document = JSONObject(raw)
            val manifest = ServiceManifestParser.parse(document)
            val value = VerifiedServiceManifest(
                manifest,
                ServiceManifestParser.hash(document),
                ServiceManifestParser.fingerprint(
                    ServiceManifestParser.parseEncryptionKey(manifest.encryptionPublicKey),
                ),
                "preview-certificate-fingerprint",
                requireNotNull(URI(manifest.serviceOrigin).host),
            )
            verified = value
            manifestDocument = document
            showDisclosure(value)
        } catch (_: Exception) {
            fail("Preview provider manifest is invalid")
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.data?.takeIf { it.scheme == CALLBACK_SCHEME }?.let(::handleCallback)
    }

    private fun fetchProvider(input: String) {
        executor.execute {
            try {
                val origin = ServiceManifestParser.canonicalOrigin(input.trim())
                val connection = URL("$origin/.well-known/nfc-authenticator").openConnection() as HttpsURLConnection
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.instanceFollowRedirects = false
                connection.requestMethod = "GET"
                require(connection.responseCode == 200)
                val certificate = connection.serverCertificates.first() as X509Certificate
                val envelope = JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
                require(envelope.toString().toByteArray().size <= 64 * 1024)
                val signed = ProviderManifestVerifier.verify(envelope, origin, certificate)
                val document = signed.manifest
                val manifest = ServiceManifestParser.parse(document)
                require(manifest.serviceOrigin == origin)
                checkPolicy(manifest.privacyPolicyUrl)
                val value = VerifiedServiceManifest(
                    manifest,
                    ServiceManifestParser.hash(document),
                    ServiceManifestParser.fingerprint(ServiceManifestParser.parseEncryptionKey(manifest.encryptionPublicKey)),
                    signed.certificateFingerprint,
                    signed.verifiedDomain,
                )
                runOnUiThread {
                    verified = value
                    manifestDocument = document
                    showDisclosure(value)
                }
            } catch (_: Exception) {
                runOnUiThread { fail("Provider identity, manifest, or privacy policy could not be verified.") }
            }
        }
    }

    private fun checkPolicy(url: String) {
        val connection = URL(url).openConnection() as HttpsURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.instanceFollowRedirects = true
        connection.requestMethod = "GET"
        require(connection.responseCode in 200..399)
        require(connection.url.protocol == "https")
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

    private fun showDisclosure(value: VerifiedServiceManifest) {
        val manifest = value.manifest
        var choice = 0
        val profiles = manifest.supportedProfiles.toTypedArray()
        val requested = manifest.requestedFields.joinToString("\n") {
            "• ${ServiceManifestParser.displayName(it)}: ${manifest.purposes.getValue(it)}"
        }
        AlertDialog.Builder(this)
            .setTitle("Register with ${manifest.serviceName}?")
            .setMessage(
                "Operator: ${manifest.operatorName}\n" +
                    "Identity verified for ${value.verifiedDomain}\n\n" + requested + "\n\n" +
                    "Audiences: ${manifest.allowedAudiences.joinToString()}\n" +
                    "Scopes: ${manifest.allowedScopes.joinToString()}\n\n" +
                    "Registration lifetime: ${manifest.registrationLifetimeDays} days. " +
                    "Successful authentication or an explicit renewal extends it. " +
                    "The app sends no background heartbeat.\n\n" +
                    "Data is encrypted directly to ${manifest.serviceName}. " +
                    "Deletion: ${manifest.deletionUrlOrContact}\nPrivacy: ${manifest.privacyPolicyUrl}",
            )
            .setSingleChoiceItems(profiles, choice) { _, which -> choice = which }
            .setNeutralButton("View privacy policy") { _, _ ->
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(manifest.privacyPolicyUrl)))
            }
            .setNegativeButton(R.string.dialog_button_cancel) { _, _ -> finish() }
            .setPositiveButton("Agree and register") { _, _ ->
                selectedProfile = profiles[choice]
                startAccountLink()
            }
            .setOnCancelListener { finish() }
            .show()
    }

    private fun startAccountLink() {
        val service = verified ?: return fail("Provider registration expired")
        val profile = selectedProfile ?: return fail("Credential profile is missing")
        val publicKey = keys.getPublicKeyAsString(
            service.manifest.serviceOrigin,
            service.manifest.serviceId,
            profile,
        )
        executor.execute {
            try {
                val response = postJson(
                    service.manifest.registrationEndpoint,
                    JSONObject().put("profile", profile).put("public_key", publicKey),
                )
                registrationId = response.getString("registration_id")
                val authorizationUrl = response.getString("authorization_url")
                runOnUiThread { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(authorizationUrl))) }
            } catch (_: Exception) {
                runOnUiThread { fail("Could not start provider account linking") }
            }
        }
    }

    private fun handleCallback(uri: Uri) {
        val id = uri.getQueryParameter("registration_id") ?: return fail("Registration callback is incomplete")
        val code = uri.getQueryParameter("completion_code") ?: return fail("Registration callback is incomplete")
        if (registrationId != id || verified == null || selectedProfile == null) {
            return fail("Registration state was lost; please start again")
        }
        completionCode = code
        val payload = completionPayload(id, code)
        if (selectedProfile == ServiceManifestParser.PROFILE_BIOMETRIC) {
            biometricRegistrationProof(payload)
        } else {
            val service = verified!!.manifest
            completeAccountLink(
                keys.sign(service.serviceOrigin, service.serviceId, selectedProfile!!, payload),
            )
        }
    }

    private fun biometricRegistrationProof(payload: ByteArray) {
        val service = verified?.manifest ?: return fail("Provider registration expired")
        val signature = keys.signatureForAuthentication(
            service.serviceOrigin,
            service.serviceId,
            ServiceManifestParser.PROFILE_BIOMETRIC,
        )
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val unlocked = result.cryptoObject?.signature ?: error("Key was not unlocked")
                        unlocked.update(payload)
                        completeAccountLink(Base64.encodeToString(unlocked.sign(), Base64.NO_WRAP))
                    } catch (_: Exception) {
                        fail("Registration key proof failed")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    fail("Registration was cancelled")
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Register with ${service.serviceName}")
            .setSubtitle("Create the biometric credential")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.dialog_button_cancel))
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    private fun completeAccountLink(signature: String) {
        val value = verified ?: return fail("Provider registration expired")
        val id = registrationId ?: return fail("Registration ID is missing")
        val code = completionCode ?: return fail("Completion code is missing")
        executor.execute {
            try {
                val response = postJson(
                    value.manifest.registrationEndpoint.trimEnd('/') + "/$id/complete",
                    JSONObject().put("completion_code", code).put("signature", signature),
                )
                val manifest = value.manifest
                require(response.getString("service_id") == manifest.serviceId)
                require(response.getString("profile") == selectedProfile)
                require(response.getInt("key_version") == 1)
                val now = System.currentTimeMillis() / 1000L
                val expiresAtSeconds = response.getLong("registration_expires_at")
                require(expiresAtSeconds > now)
                require(expiresAtSeconds - now <= (manifest.registrationLifetimeDays + 1L) * 86_400L)
                val record = ReaderInfo(
                    manifest.serviceOrigin,
                    manifest.serviceId,
                    manifest.serviceName,
                    manifest.operatorName,
                    response.getString("credential_id"),
                    selectedProfile!!,
                    null,
                    manifest.privacyPolicyUrl,
                    manifest.privacyNoticeVersion,
                    manifest.requestedFields,
                    manifest.purposes,
                    manifest.deletionUrlOrContact,
                    value.encryptionKeyFingerprint,
                    value.certificateFingerprint,
                    value.verifiedDomain,
                    value.manifestHash,
                    System.currentTimeMillis(),
                    expiresAtSeconds * 1000L,
                    manifest.allowedAudiences,
                    manifest.allowedScopes,
                )
                require(database.registerReader(record))
                runOnUiThread {
                    Toast.makeText(this, "Registered with ${manifest.serviceName}", Toast.LENGTH_LONG).show()
                    PendingRegistrationSession.clear()
                    finish()
                }
            } catch (_: Exception) {
                runOnUiThread { fail("Provider registration could not be completed") }
            }
        }
    }

    private fun postJson(url: String, body: JSONObject): JSONObject {
        val connection = URL(url).openConnection() as HttpsURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.requestMethod = "POST"
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("Accept", "application/json")
        connection.doOutput = true
        connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        require(connection.responseCode in 200..299)
        return JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
    }

    private fun completionPayload(id: String, code: String) =
        "NFCAuth-v4-registration-complete\u0000$id\u0000$code".toByteArray(Charsets.UTF_8)

    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun fail(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        PendingRegistrationSession.clear()
        finish()
    }

    override fun onDestroy() {
        executor.shutdownNow()
        database.close()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_ORIGIN = "provider_origin"
        const val EXTRA_PREVIEW_MANIFEST = "preview_provider_manifest"
        private const val CALLBACK_SCHEME = "nfcauth"
    }
}
