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
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.QuicPacket;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EncryptionWorkerPoolTest {

    private EncryptionWorkerPool pool;

    @AfterEach
    void tearDown() {
        if (pool != null) {
            pool.shutdown();
        }
    }

    @Test
    void allEnqueuedItemsAreEncryptedAndForwardedToSink() throws Exception {
        int items = 500;
        Aead aead = mock(Aead.class);
        when(aead.getIv()).thenReturn(new byte[12]);
        ConcurrentLinkedQueue<EncryptedPacket> outputs = new ConcurrentLinkedQueue<>();
        CountDownLatch allReceived = new CountDownLatch(items);

        pool = new EncryptionWorkerPool(4, 256, "test-encrypt", out -> {
            outputs.add(out);
            allReceived.countDown();
        }, mock(Logger.class));

        for (int i = 0; i < items; i++) {
            QuicPacket packet = mock(QuicPacket.class);
            byte[] payload = ("pkt-" + i).getBytes();
            when(packet.generatePacketBytes(any(Aead.class))).thenReturn(payload);
            when(packet.getPacketNumber()).thenReturn((long) i);
            pool.enqueue(new PendingEncryption(packet, i, EncryptionLevel.App, aead, p -> {}));
        }

        assertThat(allReceived.await(15, TimeUnit.SECONDS)).isTrue();
        assertThat(outputs).hasSize(items);

        // Verify each PN appears exactly once in the output (no races dropped any item).
        Set<Long> seen = ConcurrentHashMap.newKeySet();
        for (EncryptedPacket ep : outputs) {
            assertThat(seen.add(ep.getPacketNumber())).as("duplicate pn=" + ep.getPacketNumber()).isTrue();
            assertThat(ep.isSkipped()).isFalse();
            assertThat(ep.getDatagramBytes()).isNotNull();
        }
        assertThat(seen).hasSize(items);
    }

    @Test
    void enqueueBlocksWhenQueueIsFull() throws Exception {
        // poolSize=1, queue capacity=2, but the single worker is blocked behind a latch.
        CountDownLatch holdWorker = new CountDownLatch(1);
        Aead aead = mock(Aead.class);
        when(aead.getIv()).thenReturn(new byte[12]);

        pool = new EncryptionWorkerPool(1, 2, "test-bp", out -> {}, mock(Logger.class));

        QuicPacket blockingPacket = mock(QuicPacket.class);
        when(blockingPacket.generatePacketBytes(any())).thenAnswer(invocation -> {
            holdWorker.await();
            return new byte[8];
        });
        pool.enqueue(new PendingEncryption(blockingPacket, 0, EncryptionLevel.App, aead, p -> {}));

        // Worker is now busy waiting on holdWorker; queue can hold 2 more before blocking.
        QuicPacket dummy = mock(QuicPacket.class);
        when(dummy.generatePacketBytes(any())).thenReturn(new byte[8]);
        pool.enqueue(new PendingEncryption(dummy, 1, EncryptionLevel.App, aead, p -> {}));
        pool.enqueue(new PendingEncryption(dummy, 2, EncryptionLevel.App, aead, p -> {}));

        AtomicInteger enqueued = new AtomicInteger();
        Thread blocker = new Thread(() -> {
            try {
                pool.enqueue(new PendingEncryption(dummy, 3, EncryptionLevel.App, aead, p -> {}));
                enqueued.incrementAndGet();
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        blocker.setDaemon(true);
        blocker.start();

        // Give the blocker time to attempt and block on put().
        Thread.sleep(200);
        assertThat(enqueued.get()).isEqualTo(0);

        // Release the worker; the blocker should now proceed.
        holdWorker.countDown();
        blocker.join(5000);
        assertThat(blocker.isAlive()).isFalse();
        assertThat(enqueued.get()).isEqualTo(1);
    }

    @Test
    void workerErrorEmitsSkippedMarkerAndKeepsPoolAlive() throws Exception {
        Aead aead = mock(Aead.class);
        when(aead.getIv()).thenReturn(new byte[12]);
        ConcurrentLinkedQueue<EncryptedPacket> outputs = new ConcurrentLinkedQueue<>();
        CountDownLatch received = new CountDownLatch(2);

        pool = new EncryptionWorkerPool(1, 8, "test-err", out -> {
            outputs.add(out);
            received.countDown();
        }, mock(Logger.class));

        QuicPacket failingPacket = mock(QuicPacket.class);
        when(failingPacket.generatePacketBytes(any())).thenThrow(new RuntimeException("boom"));
        pool.enqueue(new PendingEncryption(failingPacket, 7, EncryptionLevel.App, aead, p -> {}));

        QuicPacket okPacket = mock(QuicPacket.class);
        when(okPacket.generatePacketBytes(any())).thenReturn(new byte[]{1, 2, 3});
        pool.enqueue(new PendingEncryption(okPacket, 8, EncryptionLevel.App, aead, p -> {}));

        assertThat(received.await(5, TimeUnit.SECONDS)).isTrue();

        EncryptedPacket skipped = outputs.stream().filter(EncryptedPacket::isSkipped).findFirst().orElseThrow();
        assertThat(skipped.getPacketNumber()).isEqualTo(7L);
        EncryptedPacket success = outputs.stream().filter(e -> !e.isSkipped()).findFirst().orElseThrow();
        assertThat(success.getPacketNumber()).isEqualTo(8L);
    }
}
