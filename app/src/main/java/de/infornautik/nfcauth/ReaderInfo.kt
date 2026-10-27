package de.infornautik.nfcauth

data class ReaderInfo(
    val serviceOrigin: String,
    val serviceId: String,
    val serviceName: String,
    val operatorName: String,
    val credentialId: String,
    val authenticationProfile: String,
    val alias: String?,
    val privacyPolicyUrl: String,
    val privacyNoticeVersion: String,
    val requestedFields: List<String>,
    val purposes: Map<String, String>,
    val deletionUrlOrContact: String,
    val encryptionKeyFingerprint: String,
    val certificateFingerprint: String,
    val verifiedDomain: String,
    val manifestHash: String,
    val approvedAt: Long,
    val allowedAudiences: List<String> = emptyList(),
    val allowedScopes: List<String> = emptyList(),
)
