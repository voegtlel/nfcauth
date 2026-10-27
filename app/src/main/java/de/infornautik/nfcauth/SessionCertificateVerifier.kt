package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
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

data class VerifiedSessionAuthentication(
    val service: VerifiedServiceManifest,
    val transcriptHash: ByteArray,
)

object SessionCertificateVerifier {
    private const val SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"
    private const val DOMAIN = "NFCAuth-v3-server-auth\u0000"

    fun verify(
        envelope: JSONObject,
        context: NfcSessionContext,
        selectedProfile: String,
    ): VerifiedSessionAuthentication {
        require(envelope.getInt("protocol_version") == ServiceManifestParser.PROTOCOL_VERSION)
        val manifest = ServiceManifestParser.parse(envelope.getJSONObject("manifest"))
        require(manifest.authenticationProfile == selectedProfile)
        val manifestHash = ServiceManifestParser.hash(manifest)
        val chainJson = envelope.getJSONArray("certificate_chain")
        require(chainJson.length() in 1..8)
        val factory = CertificateFactory.getInstance("X.509")
        val chain = Array(chainJson.length()) { index ->
            val encoded = Base64.decode(chainJson.getString(index), Base64.NO_WRAP)
            require(encoded.size <= 16 * 1024)
            factory.generateCertificate(encoded.inputStream()) as X509Certificate
        }
        chain.forEach(X509Certificate::checkValidity)
        val leaf = chain.first()
        val usages = leaf.keyUsage
        require(usages == null || usages.isNotEmpty() && usages[0]) { "Certificate cannot sign" }
        require(leaf.extendedKeyUsage?.contains(SERVER_AUTH_OID) == true) { "serverAuth EKU is required" }
        val host = URI(manifest.serviceOrigin).host ?: error("Service origin has no host")
        require(matchesHostname(host, leaf)) { "Certificate does not match the service origin" }
        val authType = when (leaf.publicKey) {
            is ECPublicKey -> "ECDHE_ECDSA"
            is RSAPublicKey -> "RSA"
            else -> error("Unsupported certificate key")
        }
        defaultTrustManager().checkServerTrusted(chain, authType)

        val payload = transcriptPayload(manifest, manifestHash, context)
        val signature = Base64.decode(envelope.getString("transcript_signature"), Base64.NO_WRAP)
        val algorithm = envelope.getString("signature_algorithm")
        val verifier = when {
            algorithm == "ECDSA_SHA256" && leaf.publicKey is ECPublicKey ->
                Signature.getInstance("SHA256withECDSA")
            algorithm == "RSA_PSS_SHA256" && leaf.publicKey is RSAPublicKey ->
                Signature.getInstance("RSASSA-PSS").apply {
                    setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
                }
            else -> error("Certificate key and signature algorithm do not match")
        }
        verifier.initVerify(leaf.publicKey)
        verifier.update(payload)
        require(verifier.verify(signature)) { "Session transcript signature is invalid" }
        val certificateFingerprint = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val verified = VerifiedServiceManifest(
            manifest,
            manifestHash,
            ServiceManifestParser.fingerprint(ServiceManifestParser.parseEncryptionKey(manifest.encryptionPublicKey)),
            certificateFingerprint,
            host,
        )
        return VerifiedSessionAuthentication(
            verified,
            MessageDigest.getInstance("SHA-256").digest(payload),
        )
    }

    private fun transcriptPayload(
        manifest: ServiceManifest,
        manifestHash: String,
        context: NfcSessionContext,
    ): ByteArray = ByteArrayOutputStream().also { bytes ->
        bytes.write(DOMAIN.toByteArray(Charsets.UTF_8))
        bytes.write(ServiceManifestParser.PROTOCOL_VERSION)
        DataOutputStream(bytes).use { output ->
            listOf(
                manifest.serviceOrigin.toByteArray(),
                manifest.serviceId.toByteArray(),
                manifest.authenticationProfile.toByteArray(),
                hex(manifestHash),
                context.sessionId,
                context.phoneChallenge,
                context.readerEphemeralPublicKey,
                context.phoneEphemeralPublicKey,
            ).forEach {
                output.writeInt(it.size)
                output.write(it)
            }
        }
    }.toByteArray()

    private fun defaultTrustManager(): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    private fun matchesHostname(host: String, certificate: X509Certificate): Boolean {
        val normalized = IDN.toASCII(host).lowercase()
        val names = certificate.subjectAlternativeNames ?: return false
        return names.any { entry ->
            entry.size >= 2 && entry[0] == 2 && (entry[1] as? String)?.let {
                val candidate = IDN.toASCII(it).lowercase()
                candidate == normalized ||
                    candidate.startsWith("*.") &&
                    normalized.endsWith(candidate.drop(1)) &&
                    normalized.count { char -> char == '.' } == candidate.count { char -> char == '.' }
            } == true
        }
    }

    private fun hex(value: String) = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}
