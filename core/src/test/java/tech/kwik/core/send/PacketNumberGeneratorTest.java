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

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class PacketNumberGeneratorTest {

    @Test
    void singleThreadProducesMonotonicSequenceStartingAtZero() {
        PacketNumberGenerator generator = new PacketNumberGenerator();
        for (int i = 0; i < 1000; i++) {
            assertThat(generator.nextPacketNumber()).isEqualTo(i);
        }
    }

    @Test
    void concurrentCallersGetUniqueMonotonicPacketNumbers() throws Exception {
        int threadCount = 8;
        int perThread = 1000;
        int total = threadCount * perThread;
        PacketNumberGenerator generator = new PacketNumberGenerator();
        long[] all = new long[total];
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        try {
            for (int t = 0; t < threadCount; t++) {
                final int slot = t;
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        go.await();
                        for (int i = 0; i < perThread; i++) {
                            all[slot * perThread + i] = generator.nextPacketNumber();
                        }
                    }
                    catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            ready.await();
            go.countDown();
            pool.shutdown();
            assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        }
        finally {
            pool.shutdownNow();
        }

        Set<Long> seen = new HashSet<>();
        long max = -1;
        for (long pn : all) {
            assertThat(seen.add(pn)).as("duplicate PN " + pn).isTrue();
            if (pn > max) max = pn;
        }
        // Strictly monotonic getAndIncrement: every PN in [0, total) appears exactly once.
        assertThat(seen).hasSize(total);
        assertThat(max).isEqualTo(total - 1L);
        // No gaps either: the smallest unseen PN must be == total.
        for (long i = 0; i < total; i++) {
            assertThat(seen).contains(i);
        }
    }
}
