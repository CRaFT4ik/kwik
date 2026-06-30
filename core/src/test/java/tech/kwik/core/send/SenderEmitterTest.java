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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.QuicPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SenderEmitterTest {

    private SenderEmitter emitter;

    @AfterEach
    void tearDown() {
        if (emitter != null) {
            emitter.shutdown(2000);
        }
    }

    @Test
    void emitsInPacketNumberOrderRegardlessOfSubmissionOrder() throws Exception {
        List<Long> emitted = new ArrayList<>();
        CountDownLatch allEmitted = new CountDownLatch(3);
        emitter = new SenderEmitter("test-emit", p -> {
            synchronized (emitted) {
                emitted.add(p.getPacketNumber());
            }
            allEmitted.countDown();
        }, mock(Logger.class));

        // Submit out of order BEFORE starting the loop so all three are in the heap
        // when the emitter wakes up; otherwise the 100us reorder window can elapse
        // between submits and produce a legitimate (per-spec) gap emission.
        emitter.submit(makeEncrypted(1));
        emitter.submit(makeEncrypted(3));
        emitter.submit(makeEncrypted(2));
        emitter.start();
        // expectedNextPN starts at 0; reorder window times out, expected jumps to 1,
        // then 1, 2, 3 emit in PN order.

        assertThat(allEmitted.await(5, TimeUnit.SECONDS)).isTrue();
        synchronized (emitted) {
            assertThat(emitted).containsExactly(1L, 2L, 3L);
        }
    }

    @Test
    void emitsAcrossSkippedPnAfterTimeout() throws Exception {
        List<Long> emitted = new ArrayList<>();
        CountDownLatch allEmitted = new CountDownLatch(2);
        emitter = new SenderEmitter("test-skip", p -> {
            synchronized (emitted) {
                emitted.add(p.getPacketNumber());
            }
            allEmitted.countDown();
        }, mock(Logger.class));
        emitter.start();

        // Submit PN=0 and PN=2; PN=1 is missing. After reorder timeout, PN=2 should still be emitted.
        emitter.submit(makeEncrypted(0));
        emitter.submit(makeEncrypted(2));

        assertThat(allEmitted.await(5, TimeUnit.SECONDS)).isTrue();
        synchronized (emitted) {
            assertThat(emitted).containsExactly(0L, 2L);
        }
    }

    @Test
    void skippedMarkerAdvancesExpectedPnWithoutEmission() throws Exception {
        List<Long> emitted = new ArrayList<>();
        CountDownLatch allEmitted = new CountDownLatch(2);
        emitter = new SenderEmitter("test-mark", p -> {
            synchronized (emitted) {
                emitted.add(p.getPacketNumber());
            }
            allEmitted.countDown();
        }, mock(Logger.class));
        emitter.start();

        // PN=0 real, PN=1 skipped marker, PN=2 real. Emitter should output 0 and 2 only.
        emitter.submit(makeEncrypted(0));
        emitter.submit(EncryptedPacket.skipped(1));
        emitter.submit(makeEncrypted(2));

        assertThat(allEmitted.await(5, TimeUnit.SECONDS)).isTrue();
        synchronized (emitted) {
            assertThat(emitted).containsExactly(0L, 2L);
        }
    }

    private EncryptedPacket makeEncrypted(long pn) {
        QuicPacket packet = mock(QuicPacket.class);
        when(packet.getPacketNumber()).thenReturn(pn);
        return new EncryptedPacket(pn, new byte[]{(byte) pn}, packet, p -> {}, EncryptionLevel.App);
    }
}
