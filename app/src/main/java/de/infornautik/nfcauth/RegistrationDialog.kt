package de.infornautik.nfcauth

import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.os.Looper
import android.os.Handler
import android.view.LayoutInflater
import android.view.Window
import android.view.View
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import org.json.JSONObject
import android.util.Log
import java.util.UUID
import androidx.appcompat.app.AppCompatActivity


class RegistrationDialog(
    context: Context,
    private val readerId: String,
    private val readerName: String,
) : Dialog(context, R.style.Theme_Dialog) {
    companion object {
        private const val TAG = "RegistrationDialog"
    }

    private lateinit var readerInfoText: TextView
    private lateinit var userNameInput: TextInputEditText
    private lateinit var statusText: TextView
    private lateinit var confirmButton: MaterialButton
    private lateinit var cancelButton: MaterialButton
    private var userId: String? = null
    private lateinit var keyManager: KeyManager
    private lateinit var authDatabase: AuthDatabase
    private lateinit var registrationDataManager: RegistrationDataManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d(TAG, "Creating registration dialog")
        
        try {
            requestWindowFeature(Window.FEATURE_NO_TITLE)
            setContentView(R.layout.dialog_registration)

            // Initialize views
            readerInfoText = findViewById(R.id.readerInfoText)
            userNameInput = findViewById(R.id.userNameInput)
            statusText = findViewById(R.id.statusText)
            confirmButton = findViewById(R.id.confirmButton)
            cancelButton = findViewById(R.id.cancelButton)

            // Set up button listeners
            confirmButton.setOnClickListener {
                onConfirm()
            }

            cancelButton.setOnClickListener {
                dismiss()
            }

            // Generate a random user ID
            userId = UUID.randomUUID().toString()
            Log.d(TAG, "Generated user ID: $userId")

            // Set reader info
            readerInfoText.text = context.getString(R.string.reader_info_format, readerName, readerId, userId)

            keyManager = KeyManager(context)
            authDatabase = AuthDatabase(context)
            registrationDataManager = RegistrationDataManager(context)
        } catch (e: Exception) {
            Log.e(TAG, "Error creating registration dialog", e)
            throw e
        }
    }

    fun onConfirm() {
        // Create the registration response JSON
        val userName = userNameInput.text?.toString()?.trim()
        if (userName.isNullOrBlank()) {
            userNameInput.error = context.getString(R.string.registration_username_error)
            return
        }
        Log.d(TAG, "Setting user name: $userName")

        userNameInput.visibility = View.GONE
        userNameInput.isEnabled = false
        readerInfoText.text = context.getString(R.string.reader_info_with_name_format, readerName, readerId, userId, userName)

        // Create the registration response JSON
        val registrationData = JSONObject().apply {
            put("user_id", userId)
            put("user_name", userName)
            put("public_key", keyManager.getPublicKeyAsString())
            put("reader_id", readerId)
            put("reader_name", readerName)
        }
        
        registrationDataManager.setPendingRegistrationData(registrationData)
        showWaitingForReader()
    }

    fun showWaitingForReader() {
        statusText.visibility = TextView.VISIBLE
        statusText.text = context.getString(R.string.registration_waiting_message)
        confirmButton.visibility = MaterialButton.GONE
        cancelButton.text = context.getString(R.string.registration_button_cancel)

        // Start checking if registration data has been used
        Thread {
            while (true) {
                if (!registrationDataManager.hasPendingRegistrationData()) {
                    // Registration data has been used, show success dialog
                    (context as? AppCompatActivity)?.runOnUiThread {
                        showSuccessDialog()
                    } ?: Handler(Looper.getMainLooper()).post {
                        showSuccessDialog()
                    }
                    break
                }
                Thread.sleep(500) // Check every 500ms
            }
        }.start()
    }
    
    override fun dismiss() {
        // Clear any pending registration data when dialog is dismissed
        registrationDataManager.setPendingRegistrationData(null)
        super.dismiss()
    }

    private fun showSuccessDialog() {
        userNameInput.visibility = View.GONE
        userNameInput.isEnabled = false
        readerInfoText.visibility = View.GONE
        readerInfoText.isEnabled = false
        statusText.text = context.getString(R.string.registration_success)
        statusText.setTextColor(context.getColor(android.R.color.holo_green_dark))
        cancelButton.text = context.getString(R.string.registration_button_close)
        cancelButton.setOnClickListener {
            dismiss()
        }
    }
} 