package de.infornautik.nfcauth

import java.io.ByteArrayOutputStream
import java.io.InputStream

/** Bounds bytes before decoding or parsing provider-controlled content. */
object BoundedHttp {
    fun readJson(input: InputStream, maximumBytes: Int = 64 * 1024): String = input.use {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = it.read(buffer)
            if (count < 0) break
            require(output.size() + count <= maximumBytes) { "Provider response is too large" }
            output.write(buffer, 0, count)
        }
        output.toString(Charsets.UTF_8.name())
    }
}
