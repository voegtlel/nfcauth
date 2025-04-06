package de.infornautik.nfcauth

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.view.Window

class NotRegisteredDialog : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Set dialog window properties
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.activity_not_registered_dialog)
        
        // Set dialog dimensions
        window?.setLayout(
            android.view.WindowManager.LayoutParams.WRAP_CONTENT,
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
        
        // Set up close button
        findViewById<Button>(R.id.closeButton).setOnClickListener {
            finish()
        }
    }
} 