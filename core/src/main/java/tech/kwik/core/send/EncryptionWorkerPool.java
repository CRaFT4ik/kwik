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

import tech.kwik.core.log.Logger;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Fixed-size pool of worker threads that turn assembled {@link PendingEncryption}s into
 * wire-ready {@link EncryptedPacket}s by running {@code QuicPacket.generatePacketBytes(aead)}
 * (which performs both AEAD payload encryption and header protection masking).
 *
 * Backpressure: a bounded {@link LinkedBlockingQueue} sits in front of the workers; the
 * dispatcher calls {@link #enqueue} which blocks via {@code put()} once the queue fills,
 * naturally pacing the upstream send-request queue.
 *
 * Output: each worker hands its result to the {@code outputSink} callback supplied at
 * construction. The sink is expected to be thread-safe and non-blocking (typically it
 * just hands the {@link EncryptedPacket} to the {@link SenderEmitter}'s priority queue).
 *
 * Thread-safety contract on AEAD: workers may share an {@link tech.kwik.core.crypto.Aead}
 * instance, so the AEAD must be safe for concurrent {@code aeadEncrypt} /
 * {@code createHeaderProtectionMask}. The phase-2 ThreadLocal Cipher refactor in
 * {@code BaseAeadImpl} satisfies that.
 *
 * Lifecycle: {@link #shutdown} stops accepting new work, waits a grace period for in-flight
 * encryption to complete, and then interrupts stragglers; remaining queued items are not
 * encrypted (the dispatcher must drain or accept loss before shutdown).
 */
public class EncryptionWorkerPool {

    private static final long SHUTDOWN_GRACE_SECONDS = 5;

    private final int poolSize;
    private final LinkedBlockingQueue<PendingEncryption> queue;
    private final Thread[] workers;
    private final Consumer<EncryptedPacket> outputSink;
    private final Logger log;
    private volatile boolean running = true;

    /**
     * @param poolSize    number of worker threads; must be >= 1
     * @param queueCapacity  bounded queue capacity (e.g. 256); enqueue blocks once full
     * @param threadNamePrefix  prefix for worker thread names (e.g. "kwik-encrypt"); workers become "{prefix}-{n}"
     * @param outputSink  callback receiving each finished {@link EncryptedPacket}; must be thread-safe and non-blocking
     * @param log         logger for worker errors
     */
    public EncryptionWorkerPool(int poolSize, int queueCapacity, String threadNamePrefix,
                                Consumer<EncryptedPacket> outputSink, Logger log) {
        if (poolSize < 1) {
            throw new IllegalArgumentException("poolSize must be >= 1");
        }
        if (queueCapacity < 1) {
            throw new IllegalArgumentException("queueCapacity must be >= 1");
        }
        this.poolSize = poolSize;
        this.queue = new LinkedBlockingQueue<>(queueCapacity);
        this.outputSink = outputSink;
        this.log = log;
        this.workers = new Thread[poolSize];

        ThreadFactory factory = daemonThreadFactory(threadNamePrefix);
        for (int i = 0; i < poolSize; i++) {
            Thread t = factory.newThread(this::workerLoop);
            workers[i] = t;
            t.start();
        }
    }

    /**
     * Hands a {@link PendingEncryption} to the worker pool. Blocks if the queue is full;
     * this is the dispatcher's natural backpressure signal.
     *
     * @throws InterruptedException if the calling thread is interrupted while waiting for queue space
     */
    public void enqueue(PendingEncryption pending) throws InterruptedException {
        queue.put(pending);
    }

    /**
     * @return current depth of the encryption queue (informational; may change between checks)
     */
    public int queueDepth() {
        return queue.size();
    }

    /**
     * @return remaining capacity before enqueue blocks
     */
    public int remainingCapacity() {
        return queue.remainingCapacity();
    }

    /**
     * Stops accepting new work and waits up to {@value #SHUTDOWN_GRACE_SECONDS} seconds for
     * in-flight encryption to complete, then interrupts stragglers. Items still on the queue
     * when this returns are dropped.
     */
    public void shutdown() {
        running = false;
        for (Thread t : workers) {
            t.interrupt();
        }
        long deadlineMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(SHUTDOWN_GRACE_SECONDS);
        for (Thread t : workers) {
            long remaining = deadlineMillis - System.currentTimeMillis();
            if (remaining <= 0) break;
            try {
                t.join(remaining);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void workerLoop() {
        while (running) {
            PendingEncryption pending;
            try {
                pending = queue.poll(1, TimeUnit.SECONDS);
            }
            catch (InterruptedException e) {
                if (!running) {
                    return;
                }
                continue;
            }
            if (pending == null) {
                continue;
            }
            try {
                byte[] datagramBytes = pending.getPacket().generatePacketBytes(pending.getAead());
                EncryptedPacket encrypted = new EncryptedPacket(
                        pending.getPacketNumber(),
                        datagramBytes,
                        pending.getPacket(),
                        pending.getPacketLostCallback(),
                        pending.getLevel());
                outputSink.accept(encrypted);
            }
            catch (Throwable t) {
                // Workers must not die: log and continue. The packet is effectively lost; the
                // dispatcher will not see a result and the emitter timeout will skip the PN.
                log.error("Encryption worker error for pn=" + pending.getPacketNumber(), t);
                // Emit a "skipped" marker so the emitter's expectedNextPN advances and the
                // pipeline does not stall waiting for this PN.
                outputSink.accept(EncryptedPacket.skipped(pending.getPacketNumber()));
            }
        }
    }

    private static ThreadFactory daemonThreadFactory(String prefix) {
        AtomicInteger counter = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + "-" + counter.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
}
