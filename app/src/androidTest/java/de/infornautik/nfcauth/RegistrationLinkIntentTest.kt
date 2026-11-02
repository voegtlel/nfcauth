package de.infornautik.nfcauth

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.isEnabled
import org.hamcrest.Matchers.not
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Test

class RegistrationLinkIntentTest {
    @Test
    fun unknownNfcProviderRequiresConfirmationBeforeDiscovery() {
        PendingRegistrationSession.clear()
        val intent = Intent(ApplicationProvider.getApplicationContext<Context>(), UnregisteredServiceDialog::class.java)
            .putExtra(UnregisteredServiceDialog.EXTRA_ORIGIN, "https://auth.example.test")
        ActivityScenario.launch<UnregisteredServiceDialog>(intent).use {
            onView(withText(R.string.unregistered_provider_title)).check(matches(isDisplayed()))
            onView(withId(R.id.providerAddress)).check(matches(withText("https://auth.example.test")))
            onView(withText(R.string.unregistered_provider_address_label)).check(matches(isDisplayed()))
            onView(withId(R.id.closeButton)).check(matches(isDisplayed()))
            onView(withId(R.id.registerProviderButton)).check(matches(isEnabled())).perform(click())
            onView(withText(R.string.registration_link_continue)).check(matches(isDisplayed()))
            assertNull(PendingRegistrationSession.verified)
            assertNull(PendingRegistrationSession.registrationId)
            onView(withText(R.string.dialog_button_cancel)).perform(click())
        }
    }

    @Test
    fun invalidNfcProviderCannotStartRegistration() {
        val intent = Intent(ApplicationProvider.getApplicationContext<Context>(), UnregisteredServiceDialog::class.java)
            .putExtra(UnregisteredServiceDialog.EXTRA_ORIGIN, "http://auth.example.test")
        ActivityScenario.launch<UnregisteredServiceDialog>(intent).use {
            onView(withId(R.id.registerProviderButton)).check(matches(not(isEnabled())))
        }
    }

    @After
    fun clear() { PendingRegistrationSession.clear() }

    @Test
    fun linkRequiresConfirmationBeforeFetchingProvider() {
        PendingRegistrationSession.clear()
        val intent = Intent(ApplicationProvider.getApplicationContext<Context>(), RegistrationActivity::class.java)
            .setAction(Intent.ACTION_VIEW)
            .setData(Uri.parse("nfcauth://register?provider=https%3A%2F%2Fauth.example.test"))
        ActivityScenario.launch<RegistrationActivity>(intent).use {
            onView(withText(R.string.registration_link_title)).check(matches(isDisplayed()))
            onView(withText(R.string.registration_link_continue)).check(matches(isDisplayed()))
            assertNull(PendingRegistrationSession.verified)
            assertNull(PendingRegistrationSession.registrationId)
            onView(withText(R.string.dialog_button_cancel)).perform(click())
        }
    }
}
