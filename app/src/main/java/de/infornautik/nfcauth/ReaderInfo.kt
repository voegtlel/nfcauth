package de.infornautik.nfcauth

data class ReaderInfo(
    val serviceId: String,
    val serviceName: String,
    val operatorName: String,
    val identityVerified: Boolean,
    val userId: String,
    val alias: String?,
    val privacyPolicyUrl: String,
    val privacyNoticeVersion: String,
    val requestedFields: List<String>,
    val purposes: Map<String, String>,
    val deletionUrlOrContact: String,
    val encryptionKeyFingerprint: String,
    val signingKeyFingerprint: String,
    val manifestHash: String,
    val approvedAt: Long,
)
