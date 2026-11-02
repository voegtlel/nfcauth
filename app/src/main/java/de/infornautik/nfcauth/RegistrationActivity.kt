package de.infornautik.nfcauth

import android.app.AlertDialog
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.doOnAttach
import org.json.JSONObject
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class RegistrationActivity : AppCompatActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var keys: KeyManager
    private lateinit var database: AuthDatabase
    private var providerFlowStarted = false
    private var verified: VerifiedServiceManifest?
        get() = PendingRegistrationSession.verified
        set(value) { PendingRegistrationSession.verified = value }
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
        setContentView(R.layout.activity_registration)
        supportActionBar?.title = getString(R.string.registration_screen_title)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        applyRegistrationInsets()
        keys = KeyManager(this)
        database = AuthDatabase(this)
        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            intent.getStringExtra(EXTRA_PREVIEW_MANIFEST)?.let {
                showPreviewManifest(it)
                return
            }
        }
        val restored = verified
        if (savedInstanceState != null && restored != null && registrationId == null &&
            intent.data?.host != "registration-complete"
        ) {
            providerFlowStarted = true
            showDisclosure(restored)
        } else {
            handleRegistrationIntent(intent)
        }
    }

    private fun showPreviewManifest(raw: String) {
        try {
            val document = JSONObject(raw)
            val manifest = ServiceManifestParser.parse(document)
            val value = VerifiedServiceManifest(
                manifest,
                ServiceManifestParser.hash(document),
                "preview-certificate-fingerprint",
                requireNotNull(URI(manifest.serviceOrigin).host),
            )
            verified = value
            showDisclosure(value)
        } catch (_: Exception) {
            fail("Preview provider manifest is invalid")
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleRegistrationIntent(intent)
    }

    private fun handleRegistrationIntent(incoming: Intent) {
        val uri = incoming.data
        if (uri?.scheme == CALLBACK_SCHEME && uri.host == "registration-complete" &&
            uri.userInfo == null && uri.port == -1 && uri.fragment == null && uri.path.isNullOrEmpty()
        ) {
            handleCallback(uri)
            return
        }
        // A second scan must never overwrite the consent/key/browser state of a live flow.
        if (providerFlowStarted || verified != null || registrationId != null) {
            Toast.makeText(this, R.string.registration_link_busy, Toast.LENGTH_LONG).show()
            return
        }
        val origin = try {
            if (uri != null) RegistrationLink.providerOrigin(uri.toString())
            else ServiceManifestParser.canonicalOrigin(
                incoming.getStringExtra(EXTRA_ORIGIN) ?: error("Provider URL is missing"),
            )
        } catch (_: Exception) {
            Toast.makeText(this, R.string.registration_link_invalid, Toast.LENGTH_LONG).show()
            finish()
            return
        }
        providerFlowStarted = true
        if (uri == null) {
            fetchProvider(origin)
        } else {
            findViewById<TextView>(R.id.registrationStatus).text = getString(R.string.registration_link_title)
            AlertDialog.Builder(this)
                .setTitle(R.string.registration_link_title)
                .setMessage(getString(R.string.registration_link_confirmation, origin))
                .setNegativeButton(R.string.dialog_button_cancel) { _, _ -> finish() }
                .setPositiveButton(R.string.registration_link_continue) { _, _ -> fetchProvider(origin) }
                .setOnCancelListener { finish() }
                .show()
        }
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
                val envelope = JSONObject(BoundedHttp.readJson(connection.inputStream))
                require(envelope.toString().toByteArray().size <= 64 * 1024)
                val signed = ProviderManifestVerifier.verify(envelope, origin, certificate)
                val document = signed.manifest
                val manifest = ServiceManifestParser.parse(document)
                require(manifest.serviceOrigin == origin)
                checkPolicy(manifest.privacyPolicyUrl)
                val value = VerifiedServiceManifest(
                    manifest,
                    ServiceManifestParser.hash(document),
                    signed.certificateFingerprint,
                    signed.verifiedDomain,
                )
                runOnUiThread {
                    verified = value
                    showDisclosure(value)
                }
            } catch (_: Exception) {
                runOnUiThread { fail("We could not verify this provider or open its privacy policy. Check the address and try again.") }
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
        findViewById<View>(R.id.registrationStatus).visibility = View.GONE
        findViewById<View>(R.id.registrationForm).visibility = View.VISIBLE
        findViewById<TextView>(R.id.registrationTitle).text = getString(R.string.registration_title, manifest.serviceName)
        findViewById<TextView>(R.id.registrationSummary).text = getString(R.string.registration_summary, manifest.serviceName)
        findViewById<TextView>(R.id.registrationIdentity).text =
            getString(R.string.registration_identity, manifest.operatorName, value.verifiedDomain)
        findViewById<TextView>(R.id.registrationData).text = manifest.requestedFields.joinToString("\n\n") {
            val label = if (it == ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY)
                getString(R.string.registration_public_key) else getString(R.string.registration_provider_id)
            getString(R.string.registration_field_purpose, label, manifest.purposes.getValue(it))
        }
        val profiles = findViewById<RadioGroup>(R.id.registrationProfiles)
        profiles.removeAllViews()
        manifest.supportedProfiles.forEach { profile ->
            profiles.addView(RadioButton(this).apply {
                id = View.generateViewId()
                tag = profile
                text = getString(if (profile == ServiceManifestParser.PROFILE_BIOMETRIC)
                    R.string.registration_method_biometric else R.string.registration_method_tap)
                minHeight = (48 * resources.displayMetrics.density).toInt()
            })
        }
        profiles.check(profiles.getChildAt(0).id)
        findViewById<Button>(R.id.registrationPolicy).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(manifest.privacyPolicyUrl)))
        }
        findViewById<TextView>(R.id.registrationDeletion).text =
            getString(R.string.registration_deletion, manifest.deletionUrlOrContact)
        findViewById<TextView>(R.id.registrationLifetime).text =
            getString(R.string.registration_lifetime, manifest.registrationLifetimeDays, manifest.privacyNoticeVersion)
        val access = findViewById<TextView>(R.id.registrationAccess)
        access.text = getString(R.string.registration_access_details,
            manifest.allowedAudiences.joinToString(), manifest.allowedScopes.joinToString())
        findViewById<Button>(R.id.registrationAccessToggle).setOnClickListener {
            access.visibility = if (access.visibility == View.GONE) View.VISIBLE else View.GONE
        }
        findViewById<Button>(R.id.registrationCancel).setOnClickListener { cancelRegistration() }
        findViewById<Button>(R.id.registrationAgree).setOnClickListener {
            selectedProfile = profiles.findViewById<RadioButton>(profiles.checkedRadioButtonId).tag as String
            it.isEnabled = false
            startAccountLink()
        }
    }

    private fun cancelRegistration() {
        PendingRegistrationSession.clear()
        finish()
    }

    override fun onSupportNavigateUp(): Boolean { cancelRegistration(); return true }

    @Suppress("DEPRECATION")
    override fun onBackPressed() { cancelRegistration() }

    private fun applyRegistrationInsets() {
        val root = findViewById<View>(R.id.registrationRoot)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.post {
                val rootLocation = IntArray(2)
                view.getLocationOnScreen(rootLocation)
                val actionBar: View? = findViewById(androidx.appcompat.R.id.action_bar_container)
                val barLocation = IntArray(2)
                actionBar?.getLocationOnScreen(barLocation)
                val barBottom = if (actionBar?.visibility == View.VISIBLE) barLocation[1] + actionBar.height else 0
                view.setPadding(bars.left, maxOf(0, bars.top - rootLocation[1], barBottom - rootLocation[1]),
                    bars.right, bars.bottom)
            }
            insets
        }
        root.doOnAttach(ViewCompat::requestApplyInsets)
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
                val now = System.currentTimeMillis() / 1000L
                val expiresAtSeconds = response.getLong("registration_expires_at")
                require(expiresAtSeconds > now)
                require(expiresAtSeconds - now <= (manifest.registrationLifetimeDays + 1L) * 86_400L)
                val record = ServiceRegistration(
                    manifest.serviceOrigin,
                    manifest.serviceId,
                    manifest.serviceName,
                    manifest.operatorName,
                    response.getString("credential_id"),
                    selectedProfile!!,
                    manifest.privacyPolicyUrl,
                    manifest.privacyNoticeVersion,
                    manifest.requestedFields,
                    manifest.purposes,
                    manifest.deletionUrlOrContact,
                    value.certificateFingerprint,
                    value.verifiedDomain,
                    value.manifestHash,
                    System.currentTimeMillis(),
                    expiresAtSeconds * 1000L,
                    manifest.allowedAudiences,
                    manifest.allowedScopes,
                )
                require(database.saveRegistration(record))
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
        return JSONObject(BoundedHttp.readJson(connection.inputStream))
    }

    private fun completionPayload(id: String, code: String) =
        "NFCAuth-v4-registration-complete\u0000$id\u0000$code".toByteArray(Charsets.UTF_8)

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
