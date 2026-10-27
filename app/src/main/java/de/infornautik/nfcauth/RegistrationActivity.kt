package de.infornautik.nfcauth

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class RegistrationActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val manifest = intent.getStringExtra(EXTRA_MANIFEST)
        val offer = intent.getStringExtra(EXTRA_OFFER)
        val certificate = intent.getStringExtra(EXTRA_CERTIFICATE_FINGERPRINT)
        val domain = intent.getStringExtra(EXTRA_VERIFIED_DOMAIN)
        if (manifest == null || offer == null || certificate == null || domain == null) {
            finish()
            return
        }
        RegistrationDialog(this, manifest, offer, certificate, domain).apply {
            setOnDismissListener { finish() }
            show()
        }
    }

    companion object {
        const val EXTRA_MANIFEST = "manifest-v3"
        const val EXTRA_OFFER = "registration-offer-v3"
        const val EXTRA_CERTIFICATE_FINGERPRINT = "certificate-fingerprint-v3"
        const val EXTRA_VERIFIED_DOMAIN = "verified-domain-v3"
    }
}
