package de.infornautik.nfcauth

import android.app.Dialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.Window
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputLayout
import org.json.JSONObject
import java.util.UUID

class RegistrationDialog(
    context: Context,
    private val signedManifest: String,
) : Dialog(context, R.style.Theme_Dialog) {

    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var authDatabase: AuthDatabase
    private lateinit var keyManager: KeyManager
    private lateinit var registrationDataManager: RegistrationDataManager
    private lateinit var verified: VerifiedServiceManifest
    private var existingRegistration: ReaderInfo? = null
    private var policyAccessible = false
    private var registrationSubmitted = false
    private var registrationCompleted = false

    private lateinit var titleText: TextView
    private lateinit var recipientText: TextView
    private lateinit var verificationText: TextView
    private lateinit var requestedDataText: TextView
    private lateinit var encryptionText: TextView
    private lateinit var changeWarningText: TextView
    private lateinit var aliasInputLayout: TextInputLayout
    private lateinit var statusText: TextView
    private lateinit var privacyPolicyButton: MaterialButton
    private lateinit var deletionButton: MaterialButton
    private lateinit var confirmButton: MaterialButton
    private lateinit var cancelButton: MaterialButton

    private val pendingPoll = object : Runnable {
        override fun run() {
            if (!registrationDataManager.hasPendingRegistrationData()) {
                registrationCompleted = true
                showSuccess()
            } else if (isShowing) {
                mainHandler.postDelayed(this, 500)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.dialog_registration)

        bindViews()
        authDatabase = AuthDatabase(context)
        keyManager = KeyManager(context)
        registrationDataManager = RegistrationDataManager(context)

        verified = try {
            ServiceManifestParser.parseAndVerify(signedManifest)
        } catch (exception: ManifestValidationException) {
            showFatalError(exception.message ?: context.getString(R.string.registration_invalid_manifest))
            return
        }
        existingRegistration = authDatabase.getReaderInfo(verified.manifest.serviceId)
        renderDisclosure()
        startPolicyCheck()

        privacyPolicyButton.setOnClickListener {
            openUri(verified.manifest.privacyPolicyUrl)
        }
        deletionButton.setOnClickListener {
            openDeletionContact(verified.manifest.deletionUrlOrContact)
        }
        confirmButton.setOnClickListener { onConfirm() }
        cancelButton.setOnClickListener { dismiss() }
    }

    override fun dismiss() {
        mainHandler.removeCallbacks(pendingPoll)
        if (registrationSubmitted && !registrationCompleted &&
            registrationDataManager.hasPendingRegistrationData()
        ) {
            registrationDataManager.cancelPendingRegistration(keyManager)
        }
        if (::authDatabase.isInitialized) authDatabase.close()
        super.dismiss()
    }

    private fun bindViews() {
        titleText = findViewById(R.id.registrationTitleText)
        recipientText = findViewById(R.id.recipientText)
        verificationText = findViewById(R.id.verificationText)
        requestedDataText = findViewById(R.id.requestedDataText)
        encryptionText = findViewById(R.id.encryptionText)
        changeWarningText = findViewById(R.id.changeWarningText)
        aliasInputLayout = findViewById(R.id.aliasInputLayout)
        statusText = findViewById(R.id.statusText)
        privacyPolicyButton = findViewById(R.id.privacyPolicyButton)
        deletionButton = findViewById(R.id.deletionButton)
        confirmButton = findViewById(R.id.confirmButton)
        cancelButton = findViewById(R.id.cancelButton)
    }

    private fun renderDisclosure() {
        val manifest = verified.manifest
        titleText.text = context.getString(R.string.registration_title, manifest.serviceName)
        recipientText.text = context.getString(
            R.string.registration_recipient,
            manifest.serviceName,
            manifest.operatorName,
            manifest.serviceId,
            manifest.privacyNoticeVersion,
        )
        verificationText.text = if (verified.identityVerified) {
            context.getString(
                R.string.registration_identity_verified,
                verified.signingKeyFingerprint,
            )
        } else {
            context.getString(
                R.string.registration_identity_unverified,
                verified.signingKeyFingerprint,
            )
        }
        verificationText.setTextColor(
            context.getColor(
                if (verified.identityVerified) {
                    android.R.color.holo_green_dark
                } else {
                    android.R.color.holo_orange_dark
                },
            ),
        )

        requestedDataText.text = buildString {
            append(context.getString(R.string.registration_requested_data_heading))
            manifest.requestedFields.forEach { field ->
                append("\n\n• ")
                append(ServiceManifestParser.displayName(field))
                append("\n  ")
                append(manifest.purposes.getValue(field))
            }
        }
        encryptionText.text = context.getString(
            R.string.registration_encryption_confirmation,
            verified.encryptionKeyFingerprint,
        )
        aliasInputLayout.visibility = if (
            manifest.requestedFields.contains(ServiceManifestParser.FIELD_ALIAS)
        ) {
            View.VISIBLE
        } else {
            View.GONE
        }

        val changes = ServiceManifestParser.changeReasons(existingRegistration, verified)
        if (changes.isNotEmpty()) {
            changeWarningText.visibility = View.VISIBLE
            changeWarningText.text = context.getString(
                R.string.registration_reconfirmation_reason,
                changes.joinToString(", "),
            )
        }
    }

    private fun startPolicyCheck() {
        confirmButton.isEnabled = false
        statusText.visibility = View.VISIBLE
        statusText.text = context.getString(R.string.registration_policy_checking)
        Thread {
            val accessible = PrivacyPolicyValidator.isAccessible(
                verified.manifest.privacyPolicyUrl,
            )
            mainHandler.post {
                if (!isShowing || registrationSubmitted) return@post
                policyAccessible = accessible
                confirmButton.isEnabled = accessible
                statusText.text = if (accessible) {
                    context.getString(R.string.registration_policy_accessible)
                } else {
                    context.getString(R.string.registration_policy_inaccessible)
                }
                statusText.setTextColor(
                    context.getColor(
                        if (accessible) {
                            android.R.color.holo_green_dark
                        } else {
                            android.R.color.holo_red_dark
                        },
                    ),
                )
            }
        }.start()
    }

    private fun onConfirm() {
        if (!policyAccessible || registrationSubmitted) return

        val manifest = verified.manifest
        val alias = if (manifest.requestedFields.contains(ServiceManifestParser.FIELD_ALIAS)) {
            aliasInputLayout.editText?.text?.toString()?.trim().orEmpty()
        } else {
            null
        }
        if (alias != null && alias.isBlank()) {
            aliasInputLayout.error = context.getString(R.string.registration_alias_error)
            return
        }
        aliasInputLayout.error = null

        confirmButton.isEnabled = false
        cancelButton.isEnabled = false
        try {
            val userId = UUID.randomUUID().toString()
            val fields = JSONObject()
            manifest.requestedFields.forEach { field ->
                when (field) {
                    ServiceManifestParser.FIELD_ALIAS -> fields.put(field, alias)
                    ServiceManifestParser.FIELD_SERVICE_USER_ID -> fields.put(field, userId)
                    ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY -> {
                        fields.put(field, keyManager.getPublicKeyAsString(manifest.serviceId))
                    }
                }
            }
            val plaintext = JSONObject().apply {
                put("protocol_version", ServiceManifestParser.PROTOCOL_VERSION)
                put("service_id", manifest.serviceId)
                put("registration_nonce", manifest.registrationNonce)
                put("fields", fields)
            }
            val encrypted = NfcCrypto.encryptRegistration(verified, plaintext)
            keyManager.savePendingSessionKey(manifest.serviceId, encrypted.sessionKey)
            encrypted.sessionKey.fill(0)

            val pending = registrationDataManager.createPendingRecord(
                verified = verified,
                userId = userId,
                alias = alias,
                encryptedResponse = encrypted.envelope,
                wasRegistered = existingRegistration != null,
            )
            registrationDataManager.setPendingRegistrationData(pending)
            registrationSubmitted = true
            showWaitingForService()
        } catch (_: Exception) {
            keyManager.discardPendingSessionKey(
                manifest.serviceId,
                deleteSigningKey = existingRegistration == null,
            )
            confirmButton.isEnabled = true
            cancelButton.isEnabled = true
            statusText.visibility = View.VISIBLE
            statusText.setTextColor(context.getColor(android.R.color.holo_red_dark))
            statusText.text = context.getString(R.string.registration_secure_transfer_failed)
        }
    }

    private fun showWaitingForService() {
        aliasInputLayout.visibility = View.GONE
        confirmButton.visibility = View.GONE
        cancelButton.isEnabled = true
        cancelButton.text = context.getString(R.string.registration_button_cancel)
        statusText.setTextColor(context.getColor(android.R.color.darker_gray))
        statusText.text = context.getString(R.string.registration_waiting_message)
        mainHandler.post(pendingPoll)
    }

    private fun showSuccess() {
        titleText.text = context.getString(R.string.registration_success)
        recipientText.visibility = View.GONE
        verificationText.visibility = View.GONE
        requestedDataText.visibility = View.GONE
        encryptionText.visibility = View.GONE
        changeWarningText.visibility = View.GONE
        privacyPolicyButton.visibility = View.GONE
        deletionButton.visibility = View.GONE
        statusText.setTextColor(context.getColor(android.R.color.holo_green_dark))
        statusText.text = context.getString(R.string.registration_success_detail)
        cancelButton.text = context.getString(R.string.registration_button_close)
    }

    private fun showFatalError(message: String) {
        titleText.text = context.getString(R.string.registration_refused)
        recipientText.visibility = View.GONE
        verificationText.visibility = View.GONE
        requestedDataText.visibility = View.GONE
        encryptionText.visibility = View.GONE
        changeWarningText.visibility = View.GONE
        aliasInputLayout.visibility = View.GONE
        privacyPolicyButton.visibility = View.GONE
        deletionButton.visibility = View.GONE
        confirmButton.visibility = View.GONE
        statusText.visibility = View.VISIBLE
        statusText.setTextColor(context.getColor(android.R.color.holo_red_dark))
        statusText.text = message
        cancelButton.text = context.getString(R.string.registration_button_close)
        cancelButton.setOnClickListener { dismiss() }
    }

    private fun openDeletionContact(contact: String) {
        val uri = if (contact.contains("@") && !contact.startsWith("mailto:")) {
            Uri.parse("mailto:$contact")
        } else {
            Uri.parse(contact)
        }
        openUri(uri.toString())
    }

    private fun openUri(value: String) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(value)))
        } catch (_: Exception) {
            statusText.visibility = View.VISIBLE
            statusText.setTextColor(context.getColor(android.R.color.holo_red_dark))
            statusText.text = context.getString(R.string.registration_link_open_failed)
        }
    }
}
