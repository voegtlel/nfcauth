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
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Test

class RegistrationLinkIntentTest {
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
