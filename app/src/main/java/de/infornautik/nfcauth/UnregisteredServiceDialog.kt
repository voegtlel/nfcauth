package de.infornautik.nfcauth

import android.app.Activity
import android.os.Bundle
import android.widget.Button
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
        
        findViewById<Button>(R.id.closeButton).setOnClickListener {
            finish()
        }
    }
} 