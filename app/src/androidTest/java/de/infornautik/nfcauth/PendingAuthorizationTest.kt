package de.infornautik.nfcauth

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PendingAuthorizationTest {
    @After
    fun clear() { PendingAuthorizationStore.cancel() }

    @Test
    fun stalePromptCannotApproveOrCancelReplacement() {
        PendingAuthorizationStore.cancel()
        val first = pending("first")
        PendingAuthorizationStore.put(first)
        PendingAuthorizationStore.cancel(first.requestHash)
        val replacement = pending("replacement")
        PendingAuthorizationStore.put(replacement)
        PendingAuthorizationStore.cancel(first.requestHash)
        assertThrows(IllegalArgumentException::class.java) {
            PendingAuthorizationStore.approve(first.requestHash, JSONObject())
        }
        assertEquals(replacement, PendingAuthorizationStore.get())
        PendingAuthorizationStore.approve(replacement.requestHash, JSONObject())
    }

    private fun pending(hash: String) = PendingAuthorization(
        JSONObject().put("transaction_id", hash), hash, "https://example.test",
        "service", "terminal", "credential", "biometric",
        System.currentTimeMillis() / 1000L + 120,
    )
}
