package de.infornautik.nfcauth

import android.os.Bundle
import android.text.method.LinkMovementMethod
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class AppPrivacyPolicyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_privacy_policy)
        findViewById<TextView>(R.id.privacyPolicyText).movementMethod =
            LinkMovementMethod.getInstance()
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.app_privacy_policy_title)
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
