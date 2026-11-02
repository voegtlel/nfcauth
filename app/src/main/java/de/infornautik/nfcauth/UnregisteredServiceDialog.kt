package de.infornautik.nfcauth

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.view.Window

class UnregisteredServiceDialog : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.activity_unregistered_service_dialog)

        window?.setLayout(
            android.view.WindowManager.LayoutParams.WRAP_CONTENT,
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
        val origin = runCatching {
            val value = requireNotNull(intent.getStringExtra(EXTRA_ORIGIN))
            require(value.length <= 2048)
            ServiceManifestParser.canonicalOrigin(value)
        }.getOrNull()
        findViewById<TextView>(R.id.messageTextView).text = if (origin != null) {
            getString(R.string.unregistered_provider_message, origin)
        } else getString(R.string.unregistered_provider_invalid)
        findViewById<Button>(R.id.registerProviderButton).apply {
            isEnabled = origin != null
            setOnClickListener {
                if (origin != null) {
                    val link = Uri.Builder().scheme("nfcauth").authority("register")
                        .appendQueryParameter("provider", origin).build()
                    startActivity(Intent(this@UnregisteredServiceDialog, RegistrationActivity::class.java)
                        .setAction(Intent.ACTION_VIEW).setData(link))
                    finish()
                }
            }
        }
        
        findViewById<Button>(R.id.closeButton).setOnClickListener {
            finish()
        }
    }
    companion object {
        const val EXTRA_ORIGIN = "provider_origin"
    }
} 