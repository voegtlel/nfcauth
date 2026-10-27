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

class RegistrationDialog(
    context: Context,
    private val manifestJson: String,
    private val offerJson: String,
    private val certificateFingerprint: String,
    private val verifiedDomain: String,
) : Dialog(context, R.style.Theme_Dialog) {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var database: AuthDatabase
    private lateinit var keys: KeyManager
    private lateinit var data: RegistrationDataManager
    private lateinit var verified: VerifiedServiceManifest
    private lateinit var offer: JSONObject
    private var existing: ReaderInfo? = null
    private var policyAccessible = false
    private var submitted = false
    private var completed = false
    private lateinit var title: TextView
    private lateinit var recipient: TextView
    private lateinit var verification: TextView
    private lateinit var requested: TextView
    private lateinit var encryption: TextView
    private lateinit var change: TextView
    private lateinit var alias: TextInputLayout
    private lateinit var status: TextView
    private lateinit var privacy: MaterialButton
    private lateinit var deletion: MaterialButton
    private lateinit var confirm: MaterialButton
    private lateinit var cancel: MaterialButton

    private val poll = object : Runnable {
        override fun run() {
            if (!data.hasPendingRegistrationData()) {
                completed = true
                title.text = context.getString(R.string.registration_success)
                listOf(recipient, verification, requested, encryption, change, alias, privacy, deletion, confirm)
                    .forEach { it.visibility = View.GONE }
                status.text = context.getString(R.string.registration_success_detail)
                cancel.text = context.getString(R.string.registration_button_close)
            } else if (isShowing) {
                handler.postDelayed(this, 500)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        setContentView(R.layout.dialog_registration)
        title = findViewById(R.id.registrationTitleText)
        recipient = findViewById(R.id.recipientText)
        verification = findViewById(R.id.verificationText)
        requested = findViewById(R.id.requestedDataText)
        encryption = findViewById(R.id.encryptionText)
        change = findViewById(R.id.changeWarningText)
        alias = findViewById(R.id.aliasInputLayout)
        status = findViewById(R.id.statusText)
        privacy = findViewById(R.id.privacyPolicyButton)
        deletion = findViewById(R.id.deletionButton)
        confirm = findViewById(R.id.confirmButton)
        cancel = findViewById(R.id.cancelButton)
        database = AuthDatabase(context)
        keys = KeyManager(context)
        data = RegistrationDataManager(context)
        try {
            val manifestObject = JSONObject(manifestJson)
            val manifest = ServiceManifestParser.parse(manifestObject)
            offer = JSONObject(offerJson)
            require(offer.getInt("protocol_version") == 3)
            require(offer.getString("service_id") == manifest.serviceId)
            require(offer.getString("authentication_profile") == manifest.authenticationProfile)
            require(offer.getString("manifest_hash") == ServiceManifestParser.hash(manifest))
            require(offer.getString("credential_id").length in 16..255)
            require(offer.getString("registration_nonce").length == 64)
            verified = VerifiedServiceManifest(
                manifest,
                ServiceManifestParser.hash(manifest),
                ServiceManifestParser.fingerprint(ServiceManifestParser.parseEncryptionKey(manifest.encryptionPublicKey)),
                certificateFingerprint,
                verifiedDomain,
            )
        } catch (_: Exception) {
            title.text = context.getString(R.string.registration_refused)
            confirm.visibility = View.GONE
            return
        }
        existing = database.getReaderInfo(verified.manifest.serviceId, verified.manifest.authenticationProfile)
        render()
        checkPolicy()
        privacy.setOnClickListener { open(verified.manifest.privacyPolicyUrl) }
        deletion.setOnClickListener { openDeletion(verified.manifest.deletionUrlOrContact) }
        confirm.setOnClickListener { confirmRegistration() }
        cancel.setOnClickListener { dismiss() }
    }

    override fun dismiss() {
        handler.removeCallbacks(poll)
        if (submitted && !completed && data.hasPendingRegistrationData()) data.cancelPendingRegistration(keys)
        if (::database.isInitialized) database.close()
        super.dismiss()
    }

    private fun render() {
        val manifest = verified.manifest
        title.text = context.getString(R.string.registration_title, manifest.serviceName)
        recipient.text = context.getString(
            R.string.registration_recipient, manifest.serviceName, manifest.operatorName,
            manifest.serviceId, manifest.privacyNoticeVersion,
        )
        verification.text = context.getString(R.string.registration_identity_verified, verifiedDomain)
        requested.text = buildString {
            append(context.getString(R.string.registration_requested_data_heading))
            manifest.requestedFields.forEach {
                append("\n\n• ")
                append(ServiceManifestParser.displayName(it))
                append("\n  ")
                append(manifest.purposes.getValue(it))
            }
        }
        encryption.text = context.getString(
            R.string.registration_encryption_confirmation, verified.encryptionKeyFingerprint,
        )
        alias.visibility = if (manifest.requestedFields.contains(ServiceManifestParser.FIELD_ALIAS)) View.VISIBLE else View.GONE
        val reasons = ServiceManifestParser.changeReasons(existing, verified)
        if (reasons.isNotEmpty()) {
            change.visibility = View.VISIBLE
            change.text = context.getString(R.string.registration_reconfirmation_reason, reasons.joinToString())
        }
    }

    private fun checkPolicy() {
        confirm.isEnabled = false
        status.visibility = View.VISIBLE
        status.text = context.getString(R.string.registration_policy_checking)
        Thread {
            val accessible = PrivacyPolicyValidator.isAccessible(verified.manifest.privacyPolicyUrl)
            handler.post {
                policyAccessible = accessible
                confirm.isEnabled = accessible
                status.text = context.getString(
                    if (accessible) R.string.registration_policy_accessible
                    else R.string.registration_policy_inaccessible,
                )
            }
        }.start()
    }

    private fun confirmRegistration() {
        if (!policyAccessible || submitted) return
        val manifest = verified.manifest
        val aliasValue = if (manifest.requestedFields.contains(ServiceManifestParser.FIELD_ALIAS)) {
            alias.editText?.text?.toString()?.trim().orEmpty()
        } else null
        if (aliasValue != null && aliasValue.isBlank()) {
            alias.error = context.getString(R.string.registration_alias_error)
            return
        }
        try {
            val fields = JSONObject()
            manifest.requestedFields.forEach {
                when (it) {
                    ServiceManifestParser.FIELD_ALIAS -> fields.put(it, aliasValue)
                    ServiceManifestParser.FIELD_AUTHENTICATION_PUBLIC_KEY ->
                        fields.put(it, keys.getPublicKeyAsString(manifest.serviceId, manifest.authenticationProfile))
                }
            }
            val encrypted = NfcCrypto.encryptRegistration(
                verified, offer.getString("credential_id"), offer.getString("registration_nonce"), fields,
            )
            keys.savePendingRegistration(manifest.serviceId, manifest.authenticationProfile, encrypted.sessionKey)
            encrypted.sessionKey.fill(0)
            data.setPendingRegistrationData(
                data.createPendingRecord(
                    verified, offer.getString("credential_id"), offer.getString("registration_nonce"),
                    aliasValue, encrypted.envelope, existing != null,
                ),
            )
            submitted = true
            alias.visibility = View.GONE
            confirm.visibility = View.GONE
            status.text = context.getString(R.string.registration_waiting_message)
            handler.post(poll)
        } catch (_: Exception) {
            keys.discardPendingRegistration(manifest.serviceId, manifest.authenticationProfile, existing == null)
            status.text = context.getString(R.string.registration_secure_transfer_failed)
            confirm.isEnabled = true
        }
    }

    private fun openDeletion(value: String) =
        open(if (value.contains("@") && !value.startsWith("mailto:")) "mailto:" + value else value)
    private fun open(value: String) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(value)))
        } catch (_: Exception) {
            status.text = context.getString(R.string.registration_link_open_failed)
        }
    }
}
