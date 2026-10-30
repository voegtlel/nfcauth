package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.URI
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

data class VerifiedAuthorizationMessage(val request: JSONObject, val payloadHash: ByteArray)

object AuthorizationRequestVerifier {
    private const val SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"
    private const val REQUEST_DOMAIN = "NFCAuth-v4-authorization-request\u0000"
    private const val DELIVERY_DOMAIN = "NFCAuth-v4-assertion-delivery\u0000"

    fun verifyAuthorization(
        envelope: JSONObject,
        context: NfcSessionContext,
        registration: ServiceRegistration,
        profile: String,
    ): VerifiedAuthorizationMessage = verify(envelope, context, registration, profile, false)

    fun verifyDelivery(
        envelope: JSONObject,
        context: NfcSessionContext,
        registration: ServiceRegistration,
        profile: String,
    ): VerifiedAuthorizationMessage = verify(envelope, context, registration, profile, true)

    private fun verify(
        envelope: JSONObject,
        context: NfcSessionContext,
        registration: ServiceRegistration,
        profile: String,
        delivery: Boolean,
    ): VerifiedAuthorizationMessage {
        require(envelope.getString("message_type") == if (delivery) "assertion_delivery" else "authorization")
        val request = envelope.getJSONObject("request")
        require(request.getInt("protocol_version") == 4)
        require(request.getString("service_id") == registration.serviceId)
        require(request.getString("service_origin") == registration.serviceOrigin)
        require(request.getString("terminal_id").isNotBlank())
        requireSession(request.getJSONObject("session"), context)
        val now = System.currentTimeMillis() / 1000L
        require(request.getLong("issued_at") <= now + 30 && request.getLong("expires_at") > now)
        require(request.getLong("expires_at") - request.getLong("issued_at") <= if (delivery) 30 else 120)
        if (!delivery) {
            require(request.getString("manifest_hash") == registration.manifestHash)
            require(request.getString("assurance") == profile)
            require(request.getString("audience") in registration.allowedAudiences)
            val scopes = request.getJSONArray("scopes").strings()
            require(scopes.isNotEmpty() && scopes.toSet().size == scopes.size)
            require(registration.allowedScopes.containsAll(scopes))
        }

        val chain = certificateChain(envelope.getJSONArray("certificate_chain"))
        val leaf = chain.first()
        chain.forEach(X509Certificate::checkValidity)
        require(leaf.keyUsage == null || leaf.keyUsage.isNotEmpty() && leaf.keyUsage[0])
        require(leaf.extendedKeyUsage?.contains(SERVER_AUTH_OID) == true)
        val host = URI(registration.serviceOrigin).host ?: error("Service origin has no host")
        require(matchesHostname(host, leaf))
        val authType = when (leaf.publicKey) {
            is ECPublicKey -> "ECDHE_ECDSA"
            is RSAPublicKey -> "RSA"
            else -> error("Unsupported certificate key")
        }
        defaultTrustManager().checkServerTrusted(chain, authType)
        val fingerprint = sha256Hex(leaf.encoded)
        require(registration.certificateFingerprint == fingerprint) {
            "Provider certificate identity changed; online re-verification is required"
        }

        val domain = if (delivery) DELIVERY_DOMAIN else REQUEST_DOMAIN
        val payload = domain.toByteArray() + canonical(request).toByteArray(Charsets.UTF_8)
        val signature = Base64.decode(envelope.getString("signature"), Base64.NO_WRAP)
        val verifier = when {
            envelope.getString("signature_algorithm") == "ECDSA_SHA256" && leaf.publicKey is ECPublicKey ->
                Signature.getInstance("SHA256withECDSA")
            envelope.getString("signature_algorithm") == "RSA_PSS_SHA256" && leaf.publicKey is RSAPublicKey ->
                Signature.getInstance("RSASSA-PSS").apply {
                    setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
                }
            else -> error("Certificate and signature algorithm do not match")
        }
        verifier.initVerify(leaf.publicKey)
        verifier.update(payload)
        require(verifier.verify(signature))
        return VerifiedAuthorizationMessage(request, MessageDigest.getInstance("SHA-256").digest(payload))
    }

    private fun requireSession(value: JSONObject, context: NfcSessionContext) {
        fun encoded(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        require(value.getString("session_id") == encoded(context.sessionId))
        require(value.getString("phone_challenge") == encoded(context.phoneChallenge))
        require(value.getString("terminal_ephemeral_public_key") == encoded(context.readerEphemeralPublicKey))
        require(value.getString("phone_ephemeral_public_key") == encoded(context.phoneEphemeralPublicKey))
    }

    fun canonical(value: Any?): String = when (value) {
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") {
            JSONObject.quote(it) + ":" + canonical(value.get(it))
        }
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonical(value.get(it)) }
        is String -> JSONObject.quote(value)
        is Number, is Boolean -> value.toString()
        JSONObject.NULL, null -> "null"
        else -> error("Unsupported JSON value")
    }

    private fun certificateChain(values: JSONArray): Array<X509Certificate> {
        require(values.length() in 1..8)
        val factory = CertificateFactory.getInstance("X.509")
        return Array(values.length()) {
            val encoded = Base64.decode(values.getString(it), Base64.NO_WRAP)
            require(encoded.size <= 16 * 1024)
            factory.generateCertificate(encoded.inputStream()) as X509Certificate
        }
    }

    private fun defaultTrustManager(): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    private fun matchesHostname(host: String, certificate: X509Certificate): Boolean {
        val normalized = IDN.toASCII(host).lowercase()
        return certificate.subjectAlternativeNames?.any { entry ->
            entry.size >= 2 && entry[0] == 2 && (entry[1] as? String)?.let {
                val candidate = IDN.toASCII(it).lowercase()
                candidate == normalized || candidate.startsWith("*.") &&
                    normalized.endsWith(candidate.drop(1)) &&
                    normalized.count { char -> char == '.' } == candidate.count { char -> char == '.' }
            } == true
        } == true
    }

    private fun JSONArray.strings() = (0 until length()).map(::getString)
    private fun sha256Hex(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
