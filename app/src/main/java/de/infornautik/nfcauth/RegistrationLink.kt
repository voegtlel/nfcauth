package de.infornautik.nfcauth

import java.net.URI
import java.net.URLDecoder

/** An address hint only: callers must still verify discovery and request consent. */
object RegistrationLink {
    fun providerOrigin(value: String): String {
        require(value.length <= 4096)
        val uri = URI(value)
        require(uri.userInfo == null && uri.port == -1 && uri.fragment == null)
        val direct = uri.scheme == "nfcauth" && uri.host == "register" &&
            (uri.path.isNullOrEmpty() || uri.path == "/")
        val web = uri.scheme == "https" && uri.host == "voegtlel.github.io" &&
            uri.path == "/nfcauth/register.html"
        require(direct || web) { "Unsupported registration link" }
        val parts = (uri.rawQuery ?: error("Provider is missing")).split('&')
        require(parts.size == 1)
        val field = parts.single().split('=', limit = 2)
        require(field.size == 2 && field[0] == "provider")
        val origin = URLDecoder.decode(field[1], Charsets.UTF_8.name())
        require(origin.length in 1..2048 && origin == origin.trim())
        return ServiceManifestParser.canonicalOrigin(origin)
    }
}
