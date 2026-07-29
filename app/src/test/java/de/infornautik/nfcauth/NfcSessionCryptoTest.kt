package de.infornautik.nfcauth

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class NfcSessionCryptoTest {
    @Test
    fun encryptedPayloadRoundTripsWithIndependentDirectionalSequences() {
        val (readerSession, phoneSession) = createSessionPair()

        val request = """{"reader_id":"reader-1","user_name":"private"}""".toByteArray()
        val encryptedRequest = readerSession.encrypt(request, "registration")
        assertFalse(encryptedRequest.toString(Charsets.UTF_8).contains("private"))
        assertEquals(0uL, encryptedRequest.sequence())
        assertArrayEquals(request, phoneSession.decrypt(encryptedRequest, "registration"))

        val response = """{"user_id":"user-1","signature":"secret"}""".toByteArray()
        val encryptedResponse = phoneSession.encrypt(response, "authentication")
        assertEquals(0uL, encryptedResponse.sequence())
        assertArrayEquals(response, readerSession.decrypt(encryptedResponse, "authentication"))

        val secondRequest = readerSession.encrypt("second".toByteArray(), "registration")
        val secondResponse = phoneSession.encrypt("second".toByteArray(), "authentication")
        assertEquals(1uL, secondRequest.sequence())
        assertEquals(1uL, secondResponse.sequence())
    }

    @Test
    fun tamperingDoesNotAdvanceReceiveSequence() {
        val (readerSession, phoneSession) = createSessionPair()
        val encrypted = readerSession.encrypt("private".toByteArray(), "registration")
        val tampered = encrypted.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()

        assertThrows(Exception::class.java) {
            phoneSession.decrypt(tampered, "registration")
        }
        assertArrayEquals(
            "private".toByteArray(),
            phoneSession.decrypt(encrypted, "registration"),
        )
    }

    @Test
    fun duplicateSequenceIsRejected() {
        val (readerSession, phoneSession) = createSessionPair()
        val encrypted = readerSession.encrypt("private".toByteArray(), "registration")

        phoneSession.decrypt(encrypted, "registration")

        assertThrows(IllegalArgumentException::class.java) {
            phoneSession.decrypt(encrypted, "registration")
        }
    }

    @Test
    fun skippedAndOutOfOrderSequencesAreRejectedWithoutAdvancingCounter() {
        val (readerSession, phoneSession) = createSessionPair()
        val first = readerSession.encrypt("first".toByteArray(), "registration")
        val second = readerSession.encrypt("second".toByteArray(), "registration")

        assertThrows(IllegalArgumentException::class.java) {
            phoneSession.decrypt(second, "registration")
        }
        assertArrayEquals("first".toByteArray(), phoneSession.decrypt(first, "registration"))
        assertArrayEquals("second".toByteArray(), phoneSession.decrypt(second, "registration"))
    }

    @Test
    fun sequenceDirectionAndPurposeAreAuthenticated() {
        val readerSession = fixedSession(isInitiator = true)
        val phoneSession = fixedSession(isInitiator = false)
        val encrypted = readerSession.encrypt("private".toByteArray(), "registration")

        assertThrows(Exception::class.java) {
            readerSession.decrypt(encrypted, "registration")
        }
        assertThrows(Exception::class.java) {
            phoneSession.decrypt(encrypted, "authentication")
        }

        val changedSequence = encrypted.copyOf()
        changedSequence[1 + NfcSessionCrypto.SESSION_ID_LENGTH + NfcSessionCrypto.SEQUENCE_LENGTH - 1] = 1
        val receiverExpectingOne = fixedSession(isInitiator = false, receiveCounter = 1uL)
        assertThrows(Exception::class.java) {
            receiverExpectingOne.decrypt(changedSequence, "registration")
        }

        assertArrayEquals(
            "private".toByteArray(),
            phoneSession.decrypt(encrypted, "registration"),
        )
    }

    @Test
    fun failedEncryptionDoesNotAdvanceSendSequence() {
        val (readerSession, _) = createSessionPair()

        assertThrows(IllegalArgumentException::class.java) {
            readerSession.encrypt("private".toByteArray(), "")
        }

        assertEquals(
            0uL,
            readerSession.encrypt("private".toByteArray(), "registration").sequence(),
        )
    }

    @Test
    fun newSessionsResetBothDirectionalCounters() {
        val (firstReader, firstPhone) = createSessionPair()
        firstReader.encrypt("one".toByteArray(), "registration")
        firstPhone.encrypt("one".toByteArray(), "authentication")

        val (secondReader, secondPhone) = createSessionPair()

        assertEquals(0uL, secondReader.encrypt("two".toByteArray(), "registration").sequence())
        assertEquals(0uL, secondPhone.encrypt("two".toByteArray(), "authentication").sequence())
    }

    @Test
    fun exhaustedCountersCannotWrap() {
        val exhaustedSender = fixedSession(isInitiator = true, sendCounter = ULong.MAX_VALUE)
        assertThrows(IllegalArgumentException::class.java) {
            exhaustedSender.encrypt("private".toByteArray(), "registration")
        }
        val phoneEnvelope =
            fixedSession(isInitiator = false).encrypt("private".toByteArray(), "authentication")
        assertThrows(IllegalArgumentException::class.java) {
            exhaustedSender.decrypt(phoneEnvelope, "authentication")
        }

        val sender = fixedSession(isInitiator = true)
        val exhaustedReceiver = fixedSession(isInitiator = false, receiveCounter = ULong.MAX_VALUE)
        val encrypted = sender.encrypt("private".toByteArray(), "registration")
        assertThrows(IllegalArgumentException::class.java) {
            exhaustedReceiver.decrypt(encrypted, "registration")
        }
        assertThrows(IllegalArgumentException::class.java) {
            exhaustedReceiver.encrypt("private".toByteArray(), "authentication")
        }
    }

    @Test
    fun decryptsSharedReferenceVector() {
        val pythonEnvelope = (
            "02000102030405060708090a0b0c0d0e0f0000000000000000000102030405060708090a0b" +
                "8df733b07a43a68613ff843eff9f722748b8cecc728ceab45b1b4fabc0341a00d6bd7fc118"
            ).hexToBytes()
        val session = fixedSession(isInitiator = true)

        assertArrayEquals(
            """{"user_name":"Alice"}""".toByteArray(),
            session.decrypt(pythonEnvelope, "registration"),
        )
    }

    private fun createSessionPair(): Pair<NfcSessionCrypto, NfcSessionCrypto> {
        val initiator = NfcSessionCrypto.createInitiator()
        val accepted = NfcSessionCrypto.accept(initiator.request)
        return initiator.complete(accepted.response) to accepted.session
    }

    private fun fixedSession(
        isInitiator: Boolean,
        sendCounter: ULong = 0uL,
        receiveCounter: ULong = 0uL,
    ): NfcSessionCrypto {
        val sessionId = "000102030405060708090a0b0c0d0e0f".hexToBytes()
        val sharedSecret =
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978".hexToBytes()
        return NfcSessionCrypto.fromSharedSecretForTest(
            sessionId,
            sharedSecret,
            isInitiator,
            sendCounter,
            receiveCounter,
        )
    }

    private fun ByteArray.sequence(): ULong {
        val start = 1 + NfcSessionCrypto.SESSION_ID_LENGTH
        return copyOfRange(start, start + NfcSessionCrypto.SEQUENCE_LENGTH).fold(0uL) { value, byte ->
            (value shl 8) or byte.toUByte().toULong()
        }
    }

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0)
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
