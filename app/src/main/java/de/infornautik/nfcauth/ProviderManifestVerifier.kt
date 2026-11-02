package de.infornautik.nfcauth

import android.util.Base64
import org.json.JSONObject
import java.net.URI
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

data class VerifiedManifestEnvelope(
    val manifest: JSONObject,
    val certificateFingerprint: String,
    val verifiedDomain: String,
)

object ProviderManifestVerifier {
    private const val DOMAIN = "NFCAuth-v4-provider-manifest\u0000"

    fun verify(envelope: JSONObject, expectedOrigin: String, tlsCertificate: X509Certificate): VerifiedManifestEnvelope {
        val manifest = envelope.getJSONObject("manifest")
        require(manifest.getString("service_origin") == expectedOrigin)
        val chain = envelope.getJSONArray("certificate_chain")
        require(chain.length() in 1..8)
        val leaf = CertificateFactory.getInstance("X.509").generateCertificate(
            Base64.decode(chain.getString(0), Base64.NO_WRAP).inputStream(),
        ) as X509Certificate
        require(MessageDigest.isEqual(leaf.encoded, tlsCertificate.encoded)) {
            "Manifest signature must use the HTTPS service certificate"
        }
        leaf.checkValidity()
        require(leaf.keyUsage == null || leaf.keyUsage.isNotEmpty() && leaf.keyUsage[0])
        require(leaf.extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.1") == true)
        val payload = DOMAIN.toByteArray() +
            AuthorizationRequestVerifier.canonical(manifest).toByteArray(Charsets.UTF_8)
        val verifier = when {
            envelope.getString("signature_algorithm") == "ECDSA_SHA256" && leaf.publicKey is ECPublicKey ->
                Signature.getInstance("SHA256withECDSA")
            envelope.getString("signature_algorithm") == "RSA_PSS_SHA256" && leaf.publicKey is RSAPublicKey ->
                Signature.getInstance("RSASSA-PSS").apply {
                    setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
                }
            else -> error("Manifest certificate and signature algorithm do not match")
        }
        verifier.initVerify(leaf.publicKey)
        verifier.update(payload)
        require(verifier.verify(Base64.decode(envelope.getString("signature"), Base64.NO_WRAP)))
        return VerifiedManifestEnvelope(
            manifest,
            MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) },
            URI(expectedOrigin).host,
        )
    }
}
