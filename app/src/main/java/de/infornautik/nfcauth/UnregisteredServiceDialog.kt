package de.infornautik.nfcauth

import androidx.appcompat.app.AppCompatActivity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.view.View

class UnregisteredServiceDialog : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContentView(R.layout.activity_unregistered_service_dialog)

        val density = resources.displayMetrics.density
        val width = minOf((560 * density).toInt(), resources.displayMetrics.widthPixels - (48 * density).toInt())
        window?.setBackgroundDrawableResource(R.drawable.provider_notice_background)
        window?.setLayout(
            width,
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
        val origin = runCatching {
            val value = requireNotNull(intent.getStringExtra(EXTRA_ORIGIN))
            require(value.length <= 2048)
            ServiceManifestParser.canonicalOrigin(value)
        }.getOrNull()
        findViewById<TextView>(R.id.messageTextView).text = if (origin != null) {
            getString(R.string.unregistered_provider_message)
        } else getString(R.string.unregistered_provider_invalid)
        findViewById<View>(R.id.providerAddressCard).visibility = if (origin != null) View.VISIBLE else View.GONE
        findViewById<TextView>(R.id.providerAddress).text = origin
        findViewById<View>(R.id.providerRegistrationHint).visibility = if (origin != null) View.VISIBLE else View.GONE
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