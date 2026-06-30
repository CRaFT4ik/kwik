/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.send;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.ack.AckGenerator;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.recovery.RecoveryStatusProvider;
import tech.kwik.core.recovery.RttProvider;
import tech.kwik.core.test.TestClock;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies the no-restorePacketNumber contract introduced in phase 3 of the multi-sender
 * pipeline: the assembler never calls back into {@link PacketNumberGenerator} to roll back
 * an allocated PN. PN allocation happens once in {@link PacketAssembler#createPacket} (so
 * {@code estimateLength} sees the real encoded PN width); empty assembles leave the
 * allocated PN as a wire-level gap, which QUIC tolerates per RFC 9002.
 */
class PacketAssemblerNoRestoreTest extends AbstractSenderTest {

    private PacketAssembler oneRttPacketAssembler;
    private PacketNumberGenerator pnGenerator;
    private SendRequestQueue sendRequestQueue;

    @BeforeEach
    void initObjectUnderTest() {
        TestClock clock = new TestClock();
        sendRequestQueue = new SendRequestQueue(clock, null);
        VersionHolder version = new VersionHolder(Version.getDefault());
        AckGenerator ackGenerator = new AckGenerator(clock, PnSpace.App, mock(Sender.class),
                mock(RttProvider.class), mock(RecoveryStatusProvider.class));
        pnGenerator = new PacketNumberGenerator();
        oneRttPacketAssembler = new PacketAssembler(version, EncryptionLevel.App, sendRequestQueue, ackGenerator, pnGenerator);
    }

    @Test
    void consecutiveSuccessfulAssemblesProduceStrictlyIncreasingPns() {
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], false), 4 + 5, null);
        long first = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();

        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], false), 4 + 5, null);
        long second = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();

        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        long third = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();

        // Strictly increasing, no rollback. Successful assembles back-to-back are contiguous since
        // no empty assemble intervened to burn a PN.
        assertThat(second).isEqualTo(first + 1);
        assertThat(third).isEqualTo(second + 1);
    }

    @Test
    void emptyAssembleConsumesAPnWithoutRollback() {
        // Empty assemble: a PN was allocated in createPacket; no frames produced; PN is burned (gap).
        // The next successful assemble must see a strictly larger PN, never reuse the burned one.
        Optional<SendItem> empty = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]);
        assertThat(empty).isEmpty();

        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        long realPn = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();
        assertThat(realPn).isGreaterThan(0L);
    }

    @Test
    void prepareUnencryptedReturnsPacketWithStampedPn() {
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        Optional<PreEncryptionPacket> prepared = oneRttPacketAssembler.prepareUnencrypted(1200, 1232, null, new byte[0]);
        assertThat(prepared).isPresent();
        // PN already stamped in createPacket so encryption workers can size the packet correctly.
        assertThat(prepared.get().getPacket().getPacketNumber()).isGreaterThanOrEqualTo(0L);
    }
}
