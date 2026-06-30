/*
 * Copyright © 2026 Peter Doornbosch
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
package tech.kwik.core.crypto;

import org.junit.jupiter.api.Test;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;

import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Asserts that the AEAD primitives are safe to call concurrently from many threads on a single
 * Aead instance. Phase 2 of the stage-7 multi-sender work replaces the shared Cipher fields with
 * ThreadLocal; without that switch each thread would observe a partially re-initialised javax
 * crypto Cipher and produce garbage ciphertext (or throw IllegalStateException). The expectation
 * here is: every encrypt/decrypt round-trip returns the original plaintext, no exceptions, and the
 * header-protection mask is deterministic regardless of concurrency.
 */
class AeadConcurrencyTest {

    private static final int THREADS = 8;
    private static final int ITERATIONS_PER_THREAD = 1_000;

    @Test
    void aeadRoundTripIsThreadSafe() throws Exception {
        Aead aead = freshAes128Gcm();
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(THREADS);
        AtomicInteger successes = new AtomicInteger();
        AtomicReference<Throwable> firstFailure = new AtomicReference<>();

        for (int t = 0; t < THREADS; t++) {
            final int threadIndex = t;
            new Thread(() -> {
                try {
                    Random rnd = new Random(0xC0FFEEL ^ threadIndex);
                    start.await();
                    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
                        // Distinct nonce per (thread, iteration) — GCM forbids nonce reuse with
                        // the same key, so reuse would surface as AEADBadTagException on decrypt.
                        byte[] nonce = nonceFor(threadIndex, i);
                        byte[] ad = new byte[16];
                        rnd.nextBytes(ad);
                        byte[] plain = new byte[64 + rnd.nextInt(256)];
                        rnd.nextBytes(plain);

                        byte[] ct = aead.aeadEncrypt(ad, plain, nonce);
                        byte[] back = aead.aeadDecrypt(ad, ct, nonce);
                        if (back.length != plain.length) {
                            throw new AssertionError("length mismatch t=" + threadIndex + " i=" + i);
                        }
                        for (int k = 0; k < plain.length; k++) {
                            if (back[k] != plain[k]) {
                                throw new AssertionError("byte mismatch t=" + threadIndex + " i=" + i + " k=" + k);
                            }
                        }
                        successes.incrementAndGet();
                    }
                }
                catch (Throwable th) {
                    firstFailure.compareAndSet(null, th);
                }
                finally {
                    done.countDown();
                }
            }, "aead-concurrency-" + t).start();
        }

        start.countDown();
        assertThat(done.await(60, TimeUnit.SECONDS)).as("workers finished within 60s").isTrue();

        if (firstFailure.get() != null) {
            throw new AssertionError("at least one worker failed", firstFailure.get());
        }
        assertThat(successes.get()).isEqualTo(THREADS * ITERATIONS_PER_THREAD);
    }

    @Test
    void headerProtectionMaskIsThreadSafe() throws Exception {
        Aead aead = freshAes128Gcm();
        // Pre-compute the expected mask single-threaded so concurrent callers can be compared
        // against a known-good reference.
        byte[] sample = new byte[16];
        new Random(0x1234).nextBytes(sample);
        byte[] expectedMask = aead.createHeaderProtectionMask(sample);

        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(THREADS);
        AtomicReference<Throwable> firstFailure = new AtomicReference<>();
        AtomicInteger successes = new AtomicInteger();

        for (int t = 0; t < THREADS; t++) {
            new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
                        byte[] mask = aead.createHeaderProtectionMask(sample);
                        if (mask.length != expectedMask.length) {
                            throw new AssertionError("mask length mismatch");
                        }
                        for (int k = 0; k < mask.length; k++) {
                            if (mask[k] != expectedMask[k]) {
                                throw new AssertionError("mask byte mismatch at " + k);
                            }
                        }
                        successes.incrementAndGet();
                    }
                }
                catch (Throwable th) {
                    firstFailure.compareAndSet(null, th);
                }
                finally {
                    done.countDown();
                }
            }, "hp-mask-" + t).start();
        }

        start.countDown();
        assertThat(done.await(60, TimeUnit.SECONDS)).as("workers finished within 60s").isTrue();

        if (firstFailure.get() != null) {
            throw new AssertionError("at least one worker failed", firstFailure.get());
        }
        assertThat(successes.get()).isEqualTo(THREADS * ITERATIONS_PER_THREAD);
    }

    private static Aead freshAes128Gcm() {
        // Initial keys path: any 32-byte secret derives valid AES-128-GCM key + iv + hp.
        byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) secret[i] = (byte) i;
        return new Aes128Gcm(Version.getDefault(), Role.Client, true, secret, null, mock(Logger.class));
    }

    private static byte[] nonceFor(int threadIndex, int iteration) {
        // 12-byte nonce: high 4 bytes = threadIndex, low 8 bytes = iteration counter.
        byte[] n = new byte[12];
        n[0] = (byte) (threadIndex >>> 24);
        n[1] = (byte) (threadIndex >>> 16);
        n[2] = (byte) (threadIndex >>> 8);
        n[3] = (byte) threadIndex;
        long it = iteration & 0xFFFFFFFFL;
        n[4] = (byte) (it >>> 56);
        n[5] = (byte) (it >>> 48);
        n[6] = (byte) (it >>> 40);
        n[7] = (byte) (it >>> 32);
        n[8] = (byte) (it >>> 24);
        n[9] = (byte) (it >>> 16);
        n[10] = (byte) (it >>> 8);
        n[11] = (byte) it;
        return n;
    }
}
