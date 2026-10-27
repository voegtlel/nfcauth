package de.infornautik.nfcauth

import android.content.Context
import android.content.ContentValues
import android.content.Intent
import android.graphics.Bitmap
import android.os.Environment
import android.os.SystemClock
import android.provider.MediaStore
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.swipeUp
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isEnabled
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

@RunWith(AndroidJUnit4::class)
class PlayStoreScreenshotTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext

    @Before
    fun prepareDeterministicState() {
        context.deleteDatabase("auth.db")
    }

    @Test
    fun capturePlayStoreScreenshots() {
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).use { scenario ->
            waitForMainContentBelowActionBar(scenario)
            capture("01-home-empty")
        }

        val registrationIntent = Intent(context, RegistrationActivity::class.java).apply {
            putExtra(RegistrationActivity.EXTRA_MANIFEST, exampleManifest())
            putExtra(RegistrationActivity.EXTRA_OFFER, exampleOffer())
            putExtra(RegistrationActivity.EXTRA_CERTIFICATE_FINGERPRINT, EXAMPLE_SIGNING_FINGERPRINT)
            putExtra(RegistrationActivity.EXTRA_VERIFIED_DOMAIN, "voegtlel.github.io")
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

    private fun waitForMainContentBelowActionBar(
        scenario: ActivityScenario<MainActivity>,
    ) {
        val deadline = SystemClock.elapsedRealtime() + LAYOUT_TIMEOUT_MS
        var lastMeasurement = MainContentMeasurement(0, 0, 0)
        while (SystemClock.elapsedRealtime() < deadline) {
            instrumentation.waitForIdleSync()
            scenario.onActivity { activity ->
                lastMeasurement = measureMainContent(activity)
            }
            if (lastMeasurement.isBelowActionBar) return
            SystemClock.sleep(100)
        }
        assertTrue(
            "Registration count must render below the system and action bars: " +
                "statusTop=${lastMeasurement.statusTop}, " +
                "topInset=${lastMeasurement.topInset}, " +
                "actionBarSize=${lastMeasurement.actionBarSize}.",
            lastMeasurement.isBelowActionBar,
        )
    }

    private fun measureMainContent(activity: MainActivity): MainContentMeasurement {
        val statusLocation = IntArray(2)
        activity.findViewById<android.view.View>(R.id.statusText)
            .getLocationOnScreen(statusLocation)
        val root = activity.findViewById<android.view.View>(R.id.mainRoot)
        val topInset = ViewCompat.getRootWindowInsets(root)
            ?.getInsets(WindowInsetsCompat.Type.systemBars())
            ?.top ?: 0
        val value = android.util.TypedValue()
        check(
            activity.theme.resolveAttribute(
                androidx.appcompat.R.attr.actionBarSize,
                value,
                true,
            ),
        )
        return MainContentMeasurement(
            statusTop = statusLocation[1],
            topInset = topInset,
            actionBarSize = android.util.TypedValue.complexToDimensionPixelSize(
                value.data,
                activity.resources.displayMetrics,
            ),
        )
    }

    private fun capture(name: String) {
        instrumentation.waitForIdleSync()
        SystemClock.sleep(350)
        val screenshot = checkNotNull(instrumentation.uiAutomation.takeScreenshot())
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, "$name.png")
            put(MediaStore.Images.Media.MIME_TYPE, "image/png")
            put(
                MediaStore.Images.Media.RELATIVE_PATH,
                "${Environment.DIRECTORY_PICTURES}/play-store",
            )
            put(MediaStore.Images.Media.IS_PENDING, 1)
        }
        val uri = checkNotNull(
            context.contentResolver.insert(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                values,
            ),
        )
        context.contentResolver.openOutputStream(uri).use { output ->
            checkNotNull(output)
            check(screenshot.compress(Bitmap.CompressFormat.PNG, 100, output))
        }
        values.clear()
        values.put(MediaStore.Images.Media.IS_PENDING, 0)
        context.contentResolver.update(uri, values, null, null)
        screenshot.recycle()
    }

    private fun seedExampleService() {
        AuthDatabase(context).use { database ->
            check(
                database.registerReader(
                    ReaderInfo(
                        serviceOrigin = "https://voegtlel.github.io",
                        serviceId = "example.service",
                        serviceName = EXAMPLE_SERVICE_NAME,
                        operatorName = "Example Operator",
                        credentialId = "service-specific-user",
                        authenticationProfile = ServiceManifestParser.PROFILE_BIOMETRIC,
                        alias = "Personal phone",
                        privacyPolicyUrl = PRIVACY_POLICY_URL,
                        privacyNoticeVersion = "2026-07-29",
                        requestedFields = REQUESTED_FIELDS,
                        purposes = PURPOSES,
                        deletionUrlOrContact = "privacy@example.com",
                        encryptionKeyFingerprint = EXAMPLE_ENCRYPTION_FINGERPRINT,
                        certificateFingerprint = EXAMPLE_SIGNING_FINGERPRINT,
                        verifiedDomain = "voegtlel.github.io",
                        manifestHash = EXAMPLE_MANIFEST_HASH,
                        approvedAt = EXAMPLE_APPROVAL_TIME,
                    ),
                ),
            )
        }
    }

    private fun exampleManifest(): String {
        val generator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }
        val encryptionKeyPair = generator.generateKeyPair()
        val manifest = ServiceManifest(
            serviceOrigin = "https://voegtlel.github.io",
            serviceId = "example.service",
            serviceName = EXAMPLE_SERVICE_NAME,
            operatorName = "Example Operator",
            privacyPolicyUrl = PRIVACY_POLICY_URL,
            privacyNoticeVersion = "2026-07-29",
            requestedFields = REQUESTED_FIELDS,
            purposes = PURPOSES,
            deletionUrlOrContact = "privacy@example.com",
            authenticationProfile = ServiceManifestParser.PROFILE_BIOMETRIC,
            encryptionPublicKey = encryptionKeyPair.public.encoded.toBase64(),
            privacyNoticeMaterialChange = false,
        )
        return JSONObject().apply {
            put("service_origin", manifest.serviceOrigin)
            put("service_id", manifest.serviceId)
            put("service_name", manifest.serviceName)
            put("operator_name", manifest.operatorName)
            put("privacy_policy_url", manifest.privacyPolicyUrl)
            put("privacy_notice_version", manifest.privacyNoticeVersion)
            put("requested_fields", JSONArray(manifest.requestedFields))
            put("purposes", JSONObject(manifest.purposes))
            put("data_deletion_url_or_contact", manifest.deletionUrlOrContact)
            put("authentication_profile", manifest.authenticationProfile)
            put("encryption_public_key", manifest.encryptionPublicKey)
            put("privacy_notice_material_change", manifest.privacyNoticeMaterialChange)
        }.toString()
    }

    private fun exampleOffer(): String {
        val manifest = ServiceManifestParser.parse(JSONObject(exampleManifest()))
        return JSONObject()
            .put("protocol_version", 3)
            .put("service_id", manifest.serviceId)
            .put("credential_id", "service-specific-user")
            .put("authentication_profile", manifest.authenticationProfile)
            .put("manifest_hash", ServiceManifestParser.hash(manifest))
            .put("registration_nonce", "01".repeat(32))
            .toString()
    }

    private fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP)

    companion object {
        private const val EXAMPLE_SERVICE_NAME = "Example Service"
        private const val PRIVACY_POLICY_URL =
            "https://voegtlel.github.io/nfcauth/example-service-privacy.html"
        private const val POLICY_TIMEOUT_MS = 15_000L
        private const val LAYOUT_TIMEOUT_MS = 3_000L
        private const val EXAMPLE_APPROVAL_TIME = 1_785_283_200_000L
        private const val EXAMPLE_ENCRYPTION_FINGERPRINT =
            "48d7af09786b935482e8be7444f2c5fd9f85164876744f554ef59f74d6616d31"
        private const val EXAMPLE_SIGNING_FINGERPRINT =
            "b6cb527ec0e218fb76dc6f8efab0983b9292540a5fe546a59cb8fb39213243a6"
        private const val EXAMPLE_MANIFEST_HASH =
            "951dc64f2a4cf988a417681d5c23a6fb7979922bd95861711069e8be61455fae"
        private val REQUESTED_FIELDS = listOf(
            ServiceManifestParser.FIELD_ALIAS,
            ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY,
        )
        private val PURPOSES = linkedMapOf(
            ServiceManifestParser.FIELD_ALIAS to "Display a recognizable name in your account.",
            ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY to
                "Verify future NFC authentication signatures.",
        )
    }

    private data class MainContentMeasurement(
        val statusTop: Int,
        val topInset: Int,
        val actionBarSize: Int,
    ) {
        val isBelowActionBar: Boolean
            get() = statusTop >= topInset + actionBarSize
    }
}
