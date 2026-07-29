package de.infornautik.nfcauth

import java.net.HttpURLConnection
import java.net.URL

object PrivacyPolicyValidator {
    private const val CONNECT_TIMEOUT_MS = 5_000
    private const val READ_TIMEOUT_MS = 5_000
    private const val MAX_REDIRECTS = 4

    fun isAccessible(url: String): Boolean = try {
        check(url, MAX_REDIRECTS)
    } catch (_: Exception) {
        false
    }

    private fun check(url: String, redirectsRemaining: Int): Boolean {
        if (redirectsRemaining < 0 || !url.startsWith("https://", ignoreCase = true)) {
            return false
        }
        val connection = URL(url).openConnection() as? HttpURLConnection ?: return false
        return try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,text/plain")
            connection.setRequestProperty("Range", "bytes=0-1023")
            val status = connection.responseCode
            when {
                status in 200..299 -> true
                status in 300..399 -> {
                    val target = connection.getHeaderField("Location") ?: return false
                    val redirected = URL(URL(url), target).toString()
                    check(redirected, redirectsRemaining - 1)
                }
                else -> false
            }
        } finally {
            connection.disconnect()
        }
    }
}
