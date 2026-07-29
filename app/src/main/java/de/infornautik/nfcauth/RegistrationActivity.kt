package de.infornautik.nfcauth

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class RegistrationActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val signedManifest = intent.getStringExtra(EXTRA_SIGNED_MANIFEST)
        if (signedManifest.isNullOrBlank()) {
            finish()
            return
        }

        RegistrationDialog(this, signedManifest).apply {
            setOnDismissListener { finish() }
            show()
        }
    }

    companion object {
        const val EXTRA_SIGNED_MANIFEST = "signed_registration_manifest"
    }
}
