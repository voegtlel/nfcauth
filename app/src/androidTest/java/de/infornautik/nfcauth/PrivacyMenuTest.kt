package de.infornautik.nfcauth

import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.openActionBarOverflowOrOptionsMenu
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import org.junit.Test

class PrivacyMenuTest {
    @Test
    fun opensAppPolicyFromAboutMenu() {
        ActivityScenario.launch(MainActivity::class.java).use {
            onView(withText(R.string.app_privacy_policy_title)).check(doesNotExist())
            openActionBarOverflowOrOptionsMenu(ApplicationProvider.getApplicationContext<Context>())
            onView(withText(R.string.menu_about)).perform(click())
            onView(withText(R.string.view_app_privacy_policy)).perform(click())
            onView(withId(R.id.privacyPolicyText)).check(matches(withText(R.string.app_privacy_policy_text)))
        }
    }
}
