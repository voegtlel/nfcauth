package de.infornautik.nfcauth

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Environment
import android.os.SystemClock
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.swipeUp
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isEnabled
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

@RunWith(AndroidJUnit4::class)
class PlayStoreScreenshotTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private lateinit var outputDirectory: File

    @Before
    fun prepareDeterministicState() {
        context.deleteDatabase("auth.db")
        outputDirectory = File(
            context.getExternalFilesDir(Environment.DIRECTORY_PICTURES),
            "play-store",
        )
        outputDirectory.deleteRecursively()
        check(outputDirectory.mkdirs()) { "Could not create screenshot output directory." }
    }

    @Test
    fun capturePlayStoreScreenshots() {
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use {
            capture("01-home-empty")
        }

        val registrationIntent = Intent(context, RegistrationActivity::class.java).apply {
            putExtra(RegistrationActivity.EXTRA_SIGNED_MANIFEST, exampleSignedManifest())
        }
        ActivityScenario.launch<RegistrationActivity>(registrationIntent).use {
            waitForRegistrationPolicyCheck()
            capture("02-registration-disclosure")
            onView(withId(R.id.registrationScrollView)).perform(swipeUp())
            capture("03-registration-confirmation")
        }

        seedExampleService()
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use {
            capture("04-registered-service")
            onView(withText(EXAMPLE_SERVICE_NAME)).perform(click())
            capture("05-service-details")
            onView(withId(android.R.id.button2)).perform(click())
            capture("06-delete-local-confirmation")
        }

        ActivityScenario.launch<AppPrivacyPolicyActivity>(
            Intent(context, AppPrivacyPolicyActivity::class.java),
        ).use {
            capture("07-app-privacy-policy")
        }
    }

    private fun waitForRegistrationPolicyCheck() {
        val deadline = SystemClock.elapsedRealtime() + POLICY_TIMEOUT_MS
        var lastFailure: Throwable? = null
        while (SystemClock.elapsedRealtime() < deadline) {
            try {
                onView(withId(R.id.confirmButton)).check(matches(isEnabled()))
                return
            } catch (failure: Throwable) {
                lastFailure = failure
                SystemClock.sleep(250)
            }
        }
        throw AssertionError("The example privacy policy did not become accessible.", lastFailure)
    }

    private fun capture(name: String) {
        instrumentation.waitForIdleSync()
        SystemClock.sleep(350)
        val screenshot = checkNotNull(instrumentation.uiAutomation.takeScreenshot())
        FileOutputStream(File(outputDirectory, "$name.png")).use { output ->
            check(screenshot.compress(Bitmap.CompressFormat.PNG, 100, output))
        }
        screenshot.recycle()
    }

    private fun seedExampleService() {
        AuthDatabase(context).use { database ->
            check(
                database.registerReader(
                    ReaderInfo(
                        serviceId = "example.service",
                        serviceName = EXAMPLE_SERVICE_NAME,
                        operatorName = "Example Operator",
                        identityVerified = false,
                        userId = "service-specific-user",
                        alias = "Personal phone",
                        privacyPolicyUrl = PRIVACY_POLICY_URL,
                        privacyNoticeVersion = "2026-07-29",
                        requestedFields = REQUESTED_FIELDS,
                        purposes = PURPOSES,
                        deletionUrlOrContact = "privacy@example.com",
                        encryptionKeyFingerprint = EXAMPLE_ENCRYPTION_FINGERPRINT,
                        signingKeyFingerprint = EXAMPLE_SIGNING_FINGERPRINT,
                        manifestHash = EXAMPLE_MANIFEST_HASH,
                        approvedAt = EXAMPLE_APPROVAL_TIME,
                    ),
                ),
            )
        }
    }

    private fun exampleSignedManifest(): String {
        val generator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val signingKeyPair = generator.generateKeyPair()
        val encryptionKeyPair = generator.generateKeyPair()
        val manifest = ServiceManifest(
            serviceId = "example.service",
            serviceName = EXAMPLE_SERVICE_NAME,
            operatorName = "Example Operator",
            privacyPolicyUrl = PRIVACY_POLICY_URL,
            privacyNoticeVersion = "2026-07-29",
            requestedFields = REQUESTED_FIELDS,
            purposes = PURPOSES,
            deletionUrlOrContact = "privacy@example.com",
            encryptionPublicKey = encryptionKeyPair.public.encoded.toBase64(),
            registrationNonce = "0123456789abcdef0123456789abcdef",
            privacyNoticeMaterialChange = false,
        )
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKeyPair.private)
            update(ServiceManifestParser.canonicalBytes(manifest))
            sign()
        }
        val manifestJson = JSONObject().apply {
            put("service_id", manifest.serviceId)
            put("service_name", manifest.serviceName)
            put("operator_name", manifest.operatorName)
            put("privacy_policy_url", manifest.privacyPolicyUrl)
            put("privacy_notice_version", manifest.privacyNoticeVersion)
            put("requested_fields", JSONArray(manifest.requestedFields))
            put("purposes", JSONObject(manifest.purposes))
            put("data_deletion_url_or_contact", manifest.deletionUrlOrContact)
            put("encryption_public_key", manifest.encryptionPublicKey)
            put("registration_nonce", manifest.registrationNonce)
            put("privacy_notice_material_change", manifest.privacyNoticeMaterialChange)
        }
        return JSONObject().apply {
            put("protocol_version", ServiceManifestParser.PROTOCOL_VERSION)
            put("manifest", manifestJson)
            put("manifest_signing_public_key", signingKeyPair.public.encoded.toBase64())
            put("manifest_signature", signature.toBase64())
        }.toString()
    }

    private fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)

    companion object {
        private const val EXAMPLE_SERVICE_NAME = "Example Service"
        private const val PRIVACY_POLICY_URL =
            "https://voegtlel.github.io/nfcauth/example-service-privacy.html"
        private const val POLICY_TIMEOUT_MS = 15_000L
        private const val EXAMPLE_APPROVAL_TIME = 1_785_283_200_000L
        private const val EXAMPLE_ENCRYPTION_FINGERPRINT =
            "48d7af09786b935482e8be7444f2c5fd9f85164876744f554ef59f74d6616d31"
        private const val EXAMPLE_SIGNING_FINGERPRINT =
            "b6cb527ec0e218fb76dc6f8efab0983b9292540a5fe546a59cb8fb39213243a6"
        private const val EXAMPLE_MANIFEST_HASH =
            "951dc64f2a4cf988a417681d5c23a6fb7979922bd95861711069e8be61455fae"
        private val REQUESTED_FIELDS = listOf(
            ServiceManifestParser.FIELD_ALIAS,
            ServiceManifestParser.FIELD_SERVICE_USER_ID,
            ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY,
        )
        private val PURPOSES = linkedMapOf(
            ServiceManifestParser.FIELD_ALIAS to "Display a recognizable name in your account.",
            ServiceManifestParser.FIELD_SERVICE_USER_ID to
                "Identify this device only within Example Service.",
            ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY to
                "Verify future NFC authentication signatures.",
        )
    }
}
