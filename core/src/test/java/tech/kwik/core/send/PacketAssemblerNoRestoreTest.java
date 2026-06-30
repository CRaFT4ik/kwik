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
 * Verifies the PN-allocation contract introduced in phase 3 of the multi-sender pipeline:
 * the underlying {@link PacketNumberGenerator} is consumed only when an assembled packet
 * is non-empty, so there is no rollback path and no gaps between consecutive successful
 * assemble calls.
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
    void prepareUnencryptedDoesNotAllocatePnWhenEmpty() {
        // Given no send requests in the queue, prepareUnencrypted returns empty
        Optional<PreEncryptionPacket> first = oneRttPacketAssembler.prepareUnencrypted(1200, 1232, null, new byte[0]);
        assertThat(first).isEmpty();

        // When a real frame is then queued and assembled, the first PN issued must still be 0
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        Optional<SendItem> assembled = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]);
        assertThat(assembled).isPresent();
        assertThat(assembled.get().getPacket().getPacketNumber()).isEqualTo(0L);
    }

    @Test
    void consecutiveAssemblesProduceContiguousPnsWithNoGaps() {
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], false), 4 + 5, null);
        long first = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();

        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], false), 4 + 5, null);
        long second = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();

        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        long third = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]).get().getPacket().getPacketNumber();

        // No-restore contract: PNs are strictly +1 since every prepare succeeded.
        assertThat(second).isEqualTo(first + 1);
        assertThat(third).isEqualTo(second + 1);
    }

    @Test
    void emptyAssembleAttemptsDoNotBurnPns() {
        // Given a few empty assemble attempts (no queued requests), PN generator must stay at 0
        for (int i = 0; i < 10; i++) {
            Optional<SendItem> empty = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]);
            assertThat(empty).isEmpty();
        }
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        Optional<SendItem> assembled = oneRttPacketAssembler.assemble(1200, 1232, null, new byte[0]);
        assertThat(assembled).isPresent();
        assertThat(assembled.get().getPacket().getPacketNumber()).isEqualTo(0L);
    }

    @Test
    void prepareUnencryptedReturnsPacketWithoutStampedPn() {
        sendRequestQueue.addRequest(maxSize -> new StreamFrame(0, new byte[5], true), 4 + 5, null);
        Optional<PreEncryptionPacket> prepared = oneRttPacketAssembler.prepareUnencrypted(1200, 1232, null, new byte[0]);
        assertThat(prepared).isPresent();
        // Provisional PN=0 is used only for sizing; generator is untouched until the dispatcher allocates one.
        assertThat(pnGenerator.nextPacketNumber()).isEqualTo(0L);
    }
}
