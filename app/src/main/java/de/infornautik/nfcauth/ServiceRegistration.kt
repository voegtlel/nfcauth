package de.infornautik.nfcauth

data class ServiceRegistration(
    val serviceOrigin: String,
    val serviceId: String,
    val serviceName: String,
    val operatorName: String,
    val credentialId: String,
    val authenticationProfile: String,
    val privacyPolicyUrl: String,
    val privacyNoticeVersion: String,
    val requestedFields: List<String>,
    val purposes: Map<String, String>,
    val deletionUrlOrContact: String,
    val certificateFingerprint: String,
    val verifiedDomain: String,
    val manifestHash: String,
    val approvedAt: Long,
    val registrationExpiresAt: Long,
    val allowedAudiences: List<String> = emptyList(),
    val allowedScopes: List<String> = emptyList(),
)
