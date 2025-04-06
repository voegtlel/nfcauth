package de.infornautik.nfcauth

import android.app.AlertDialog
import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Bundle
import android.util.Log
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import java.security.KeyStore
import java.util.UUID

class MainActivity : AppCompatActivity() {
    private lateinit var authDatabase: AuthDatabase
    private lateinit var keyManager: KeyManager
    private var deviceUuid: String? = null
    private lateinit var statusText: TextView
    private lateinit var readersRecyclerView: RecyclerView
    private lateinit var readersAdapter: ReadersAdapter
    private lateinit var swipeRefresh: SwipeRefreshLayout

    companion object {
        private const val TAG = "MainActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize views
        statusText = findViewById(R.id.statusText)
        readersRecyclerView = findViewById(R.id.readersRecyclerView)
        swipeRefresh = findViewById(R.id.swipeRefresh)

        // Initialize database
        authDatabase = AuthDatabase(this)
        
        // Initialize KeyManager
        keyManager = KeyManager(this)
        Log.d(TAG, "KeyManager initialized")

        // Setup RecyclerView
        readersAdapter = ReadersAdapter { reader ->
            showDeleteConfirmationDialog(reader)
        }
        readersRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = readersAdapter
        }

        // Setup SwipeRefreshLayout
        swipeRefresh.setOnRefreshListener {
            loadReaders()
            swipeRefresh.isRefreshing = false
        }

        // Load initial data
        loadReaders()
    }

    private fun loadReaders() {
        val readers = authDatabase.getAllReaders()
        readersAdapter.submitList(readers)
        updateStatusText("${readers.size} reader(s) registered")
    }

    private fun showDeleteConfirmationDialog(reader: ReaderInfo) {
        AlertDialog.Builder(this)
            .setTitle("Delete Reader")
            .setMessage("Are you sure you want to delete reader '${reader.readerName}'?")
            .setPositiveButton("Delete") { _, _ ->
                deleteReader(reader)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun deleteReader(reader: ReaderInfo) {
        try {
            authDatabase.deleteReader(reader.readerId)
            loadReaders()
            Toast.makeText(this, "Reader deleted successfully", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting reader", e)
            Toast.makeText(this, "Error deleting reader", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateStatusText(message: String) {
        statusText.text = message
        Log.d(TAG, "Status updated: $message")
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy called")
        super.onDestroy()
        authDatabase.close()
        Log.d(TAG, "Database closed")
    }
} 