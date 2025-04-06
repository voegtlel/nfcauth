package de.infornautik.nfcauth

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.util.UUID

class RegistrationActivity : AppCompatActivity() {
    companion object {
        private const val TAG = "RegistrationActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val readerId = intent.getStringExtra("reader_id") ?: return finish()
        val readerName = intent.getStringExtra("reader_name") ?: return finish()

        val dialog = RegistrationDialog(this, readerId, readerName)
        dialog.setOnDismissListener {
            finish()
        }
        dialog.show()
    }
}
