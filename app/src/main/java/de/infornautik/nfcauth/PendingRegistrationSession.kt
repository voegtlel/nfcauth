package de.infornautik.nfcauth

import org.json.JSONObject

/** Process-local browser registration state; process death cancels enrollment. */
object PendingRegistrationSession {
    var verified: VerifiedServiceManifest? = null
    var manifestDocument: JSONObject? = null
    var selectedProfile: String? = null
    var registrationId: String? = null
    var completionCode: String? = null

    fun clear() {
        verified = null
        manifestDocument = null
        selectedProfile = null
        registrationId = null
        completionCode = null
    }
}
