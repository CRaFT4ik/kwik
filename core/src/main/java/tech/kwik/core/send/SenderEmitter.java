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

import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Dedicated single thread that drains encrypted packets from the {@link EncryptionWorkerPool}
 * in packet-number order and hands them to a wire-emission callback.
 *
 * Workers finish out-of-order (a small PN may take longer than a large PN that landed on a
 * less-loaded thread). The emitter restores ordering by holding a
 * {@link PriorityBlockingQueue} keyed on PN and waiting for {@code expectedNextPN} at the
 * head; on success it emits and bumps {@code expectedNextPN}.
 *
 * If a PN never arrives (worker crash, dispatcher gap, key-update edge case), the emitter
 * does not stall forever: after {@link #REORDER_TIMEOUT_NANOS} it advances past the missing
 * PN and emits the next available packet. QUIC tolerates wire gaps; this is the safety
 * valve, not the hot path.
 *
 * "Skipped" markers ({@link EncryptedPacket#isSkipped()}) carry just a PN and advance
 * {@code expectedNextPN} without producing any wire output.
 *
 * Single-threaded by design: keeps {@code recoveryManager.packetSent} and
 * {@code idleTimer.packetSent} timestamps monotonic (delegated to the
 * {@link EmissionSink}).
 */
public class SenderEmitter {

    /**
     * Maximum time the emitter waits for the head-of-line PN before giving up and
     * emitting whatever is available. 100 microseconds matches the spec's reorder window
     * recommendation and is well below typical RTT, so wire reordering remains rare.
     */
    static final long REORDER_TIMEOUT_NANOS = 100_000L;

    /**
     * Callback the emitter invokes for each ready-to-send packet. Implementations must do
     * the actual {@code socket.send(...)} plus recovery/idle/qlog accounting. Called from
     * the emitter thread only, so timestamps will be monotonic.
     */
    @FunctionalInterface
    public interface EmissionSink {
        void emit(EncryptedPacket packet);
    }

    private final PriorityBlockingQueue<EncryptedPacket> queue;
    private final EmissionSink sink;
    private final Logger log;
    private final Thread thread;
    private volatile boolean running = true;
    private long expectedNextPN = 0;

    /**
     * @param threadName  thread name (e.g. "sender-emit-{id}")
     * @param sink        emission callback invoked on the emitter thread; performs socket.send + recovery accounting
     * @param log         logger
     */
    public SenderEmitter(String threadName, EmissionSink sink, Logger log) {
        this.queue = new PriorityBlockingQueue<>(64, (a, b) -> Long.compare(a.getPacketNumber(), b.getPacketNumber()));
        this.sink = sink;
        this.log = log;
        this.thread = new Thread(this::loop, threadName);
        this.thread.setDaemon(true);
    }

    /**
     * Starts the emitter thread. Safe to call once; subsequent calls are no-ops.
     */
    public void start() {
        if (thread.getState() == Thread.State.NEW) {
            thread.start();
        }
    }

    /**
     * Adds a packet (or skip marker) to the reorder queue. Thread-safe; called from
     * encryption-pool worker threads.
     */
    public void submit(EncryptedPacket packet) {
        queue.offer(packet);
    }

    /**
     * Signals the emitter to stop and waits up to {@code timeoutMillis} for the thread to
     * exit. Best-effort drain: items still queued at the moment of interruption may be
     * dropped depending on how far past {@code expectedNextPN} they sit.
     */
    public void shutdown(long timeoutMillis) {
        running = false;
        thread.interrupt();
        try {
            thread.join(timeoutMillis);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Visible for tests / SenderImpl emergencyFlush: drains everything currently queued
     * synchronously on the calling thread, in PN order. Does NOT advance the running
     * emitter thread's expectedNextPN; intended for shutdown-time drain on a stopped
     * emitter.
     */
    public void drainNow() {
        EncryptedPacket head;
        while ((head = queue.poll()) != null) {
            emit(head);
        }
    }

    private void loop() {
        while (running) {
            try {
                EncryptedPacket head = queue.peek();
                if (head == null) {
                    // Empty queue: block waiting for the next submission.
                    head = queue.poll(1, TimeUnit.SECONDS);
                    if (head == null) {
                        continue;
                    }
                }
                else if (head.getPacketNumber() > expectedNextPN) {
                    // Out-of-order: head is ahead of expected; wait briefly for the missing
                    // PN (a slower worker) to arrive, otherwise advance past the gap.
                    long deadline = System.nanoTime() + REORDER_TIMEOUT_NANOS;
                    long remainingNanos;
                    while ((remainingNanos = deadline - System.nanoTime()) > 0) {
                        EncryptedPacket peek = queue.peek();
                        if (peek != null && peek.getPacketNumber() <= expectedNextPN) {
                            // Missing PN arrived via concurrent submit; next loop iteration picks it up.
                            break;
                        }
                        // Sleep briefly waiting for a new submission. Use a short sleep so we re-check head soon.
                        long sleepNanos = Math.min(remainingNanos, 10_000L);
                        TimeUnit.NANOSECONDS.sleep(sleepNanos);
                    }
                    // Re-peek after the wait; queue may have a new min now.
                    head = queue.peek();
                    if (head == null) {
                        continue;
                    }
                    if (head.getPacketNumber() > expectedNextPN) {
                        // Timed out waiting; advance expectedNextPN past the gap and emit current head.
                        expectedNextPN = head.getPacketNumber();
                    }
                    // Fall through; head.PN now == expectedNextPN.
                    head = queue.poll();
                    if (head == null) {
                        continue;
                    }
                }
                else {
                    head = queue.poll();
                    if (head == null) {
                        continue;
                    }
                }

                // At this point: head.PN == expectedNextPN (either originally, or after timeout-skip).
                emit(head);
                expectedNextPN = head.getPacketNumber() + 1;
            }
            catch (InterruptedException e) {
                if (!running) {
                    return;
                }
            }
            catch (Throwable t) {
                log.error("Emitter loop error", t);
            }
        }
    }

    private void emit(EncryptedPacket packet) {
        if (packet.isSkipped()) {
            return;
        }
        try {
            sink.emit(packet);
        }
        catch (Throwable t) {
            log.error("Emission sink error for pn=" + packet.getPacketNumber(), t);
        }
    }
}
