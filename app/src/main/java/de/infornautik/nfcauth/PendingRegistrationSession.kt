package de.infornautik.nfcauth

/** Process-local browser registration state; process death cancels enrollment. */
object PendingRegistrationSession {
    var verified: VerifiedServiceManifest? = null
    val completionSignatures = mutableMapOf<String, String>()
    var registrationId: String? = null
    var completionCode: String? = null

    fun clear() {
        verified = null
        completionSignatures.clear()
        registrationId = null
        completionCode = null
    }
}
