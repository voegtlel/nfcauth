package de.infornautik.nfcauth

import org.json.JSONObject

data class PendingAuthorization(
    val request: JSONObject,
    val requestHash: String,
    val serviceOrigin: String,
    val serviceId: String,
    val terminalId: String,
    val credentialId: String,
    val assurance: String,
    val expiresAt: Long,
    var assertion: JSONObject? = null,
)

/** Process-local state only. A process death intentionally cancels approval. */
object PendingAuthorizationStore {
    private var pending: PendingAuthorization? = null

    @Synchronized
    fun put(value: PendingAuthorization) {
        clearExpired()
        require(pending == null || pending?.requestHash == value.requestHash)
        pending = value
    }

    @Synchronized
    fun get(): PendingAuthorization? {
        clearExpired()
        return pending
    }

    @Synchronized
    fun approve(requestHash: String, assertion: JSONObject) {
        val value = get() ?: error("Authorization request is unavailable")
        require(value.requestHash == requestHash && value.assertion == null)
        value.assertion = assertion
    }

    @Synchronized
    fun consume(transactionId: String, requestHash: String, terminalId: String): JSONObject? {
        val value = get() ?: return null
        if (
            value.request.getString("transaction_id") != transactionId ||
            value.requestHash != requestHash || value.terminalId != terminalId
        ) return null
        val assertion = value.assertion ?: return null
        pending = null
        return assertion
    }

    @Synchronized
    fun cancel() {
        pending = null
    }

    private fun clearExpired() {
        if ((pending?.expiresAt ?: Long.MAX_VALUE) <= System.currentTimeMillis() / 1000L) pending = null
    }
}
