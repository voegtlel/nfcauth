package de.infornautik.nfcauth

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.PublicKey
import java.security.Signature

/** Pure JVM proof/policy checks, separate from Android NFC and JSON handling. */
object DiscoveryProof {
    fun payload(serviceId: String, manifestHash: String, nonce: String, binding: String): ByteArray {
        val service = serviceId.toByteArray(Charsets.UTF_8)
        require(service.size in 1..255)
        val hex = Regex("[a-f0-9]{64}")
        require(listOf(manifestHash, nonce, binding).all { hex.matches(it) })
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use {
            it.write("nfcauth-v2-credential-discovery-request\u0000".toByteArray(Charsets.UTF_8))
            it.writeShort(service.size)
            it.write(service)
            (manifestHash + nonce + binding).chunked(2).forEach { byte -> it.writeByte(byte.toInt(16)) }
        }
        return output.toByteArray()
    }

    fun verify(key: PublicKey, payload: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(payload)
            verify(signature)
        }

    fun requireApproved(existing: ReaderInfo?, verified: VerifiedServiceManifest): ReaderInfo {
        require(existing != null) { "Service has not been enrolled" }
        require(existing.serviceId == verified.manifest.serviceId)
        require(existing.privacyNoticeVersion == verified.manifest.privacyNoticeVersion)
        require(ServiceManifestParser.changeReasons(existing, verified).isEmpty())
        require(existing.requestedFields.contains("service_user_id"))
        return existing
    }
}
