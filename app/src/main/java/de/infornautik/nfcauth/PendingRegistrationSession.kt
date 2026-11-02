package de.infornautik.nfcauth

/** Process-local browser registration state; process death cancels enrollment. */
object PendingRegistrationSession {
    var verified: VerifiedServiceManifest? = null
    var selectedProfile: String? = null
    var registrationId: String? = null
    var completionCode: String? = null

    fun clear() {
        verified = null
        selectedProfile = null
        registrationId = null
        completionCode = null
    }
}
