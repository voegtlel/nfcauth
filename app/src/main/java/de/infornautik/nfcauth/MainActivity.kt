package de.infornautik.nfcauth

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.URLSpan
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import java.text.DateFormat
import java.util.Date

class MainActivity : AppCompatActivity() {
    private lateinit var authDatabase: AuthDatabase
    private lateinit var keyManager: KeyManager
    private lateinit var statusText: TextView
    private lateinit var readersAdapter: ReadersAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        authDatabase = AuthDatabase(this)
        keyManager = KeyManager(this)

        readersAdapter = ReadersAdapter(::showServiceDetails)
        findViewById<RecyclerView>(R.id.readersRecyclerView).apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = readersAdapter
        }
        val swipeRefresh = findViewById<SwipeRefreshLayout>(R.id.swipeRefresh)
        swipeRefresh.setOnRefreshListener {
            loadReaders()
            swipeRefresh.isRefreshing = false
        }
        findViewById<Button>(R.id.infoButton).setOnClickListener {
            startActivity(Intent(this, AppPrivacyPolicyActivity::class.java))
        }
        loadReaders()
    }

    override fun onResume() {
        super.onResume()
        if (::authDatabase.isInitialized) loadReaders()
    }

    override fun onDestroy() {
        authDatabase.close()
        super.onDestroy()
    }

    private fun loadReaders() {
        val readers = authDatabase.getAllReaders()
        readersAdapter.submitList(readers)
        statusText.text = resources.getQuantityString(
            R.plurals.registered_service_count,
            readers.size,
            readers.size,
        )
    }

    private fun showServiceDetails(service: ReaderInfo) {
        val details = SpannableStringBuilder().apply {
            append(getString(R.string.service_details_operator, service.operatorName))
            append("\n")
            append(
                if (service.identityVerified) {
                    getString(R.string.service_details_verified)
                } else {
                    getString(R.string.service_details_unverified)
                },
            )
            append("\n")
            append(getString(R.string.service_details_notice, service.privacyNoticeVersion))
            append("\n")
            append(
                getString(
                    R.string.service_details_approved,
                    DateFormat.getDateTimeInstance().format(Date(service.approvedAt)),
                ),
            )
            append("\n\n")
            append(getString(R.string.service_details_data_heading))
            service.requestedFields.forEach { field ->
                append("\n• ")
                append(ServiceManifestParser.displayName(field))
                append(": ")
                append(service.purposes[field].orEmpty())
            }
            append("\n\n")
            append(getString(R.string.service_details_encryption_fingerprint))
            append("\n")
            append(service.encryptionKeyFingerprint)
            append("\n\n")
            appendLink(
                getString(R.string.registration_view_privacy_policy),
                service.privacyPolicyUrl,
            )
            append("\n")
            appendLink(
                getString(R.string.registration_view_deletion_instructions),
                deletionUri(service.deletionUrlOrContact),
            )
        }

        val dialog = AlertDialog.Builder(this)
            .setTitle(service.serviceName)
            .setMessage(details)
            .setPositiveButton(R.string.dialog_button_close, null)
            .setNegativeButton(R.string.delete_local_registration) { _, _ ->
                confirmLocalDeletion(service)
            }
            .create()
        dialog.setOnShowListener {
            dialog.findViewById<TextView>(android.R.id.message)?.movementMethod =
                LinkMovementMethod.getInstance()
        }
        dialog.show()
    }

    private fun confirmLocalDeletion(service: ReaderInfo) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_local_registration_title)
            .setMessage(
                getString(
                    R.string.delete_local_registration_message,
                    service.serviceName,
                ),
            )
            .setPositiveButton(R.string.delete_local_registration) { _, _ ->
                deleteLocalRegistration(service)
            }
            .setNegativeButton(R.string.dialog_button_cancel, null)
            .show()
    }

    private fun deleteLocalRegistration(service: ReaderInfo) {
        try {
            keyManager.deleteServiceCredentials(service.serviceId)
            authDatabase.deleteReader(service.serviceId)
            loadReaders()
            Toast.makeText(
                this,
                R.string.delete_local_registration_success,
                Toast.LENGTH_SHORT,
            ).show()
        } catch (_: Exception) {
            Toast.makeText(
                this,
                R.string.delete_local_registration_failed,
                Toast.LENGTH_SHORT,
            ).show()
        }
    }

    private fun SpannableStringBuilder.appendLink(label: String, url: String) {
        val start = length
        append(label)
        setSpan(URLSpan(url), start, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    private fun deletionUri(value: String): String =
        if (value.contains("@") && !value.startsWith("mailto:")) "mailto:$value" else value
}
