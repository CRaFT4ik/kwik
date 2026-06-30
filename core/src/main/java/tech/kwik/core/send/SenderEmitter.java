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

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

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
    /**
     * Tracks PNs that the dispatcher has submitted to the encryption pool but the emitter has
     * not yet emitted. Used to distinguish wire-level PN gaps (PNs the dispatcher burned, e.g.
     * via an empty assemble that consumed the shared App+ZeroRTT PN generator) from genuine
     * worker reordering (a worker still encrypting a PN below the emitter head). Bounded by
     * encryption pool capacity + reorder window, so size stays small.
     */
    private final ConcurrentSkipListSet<Long> inflightPns = new ConcurrentSkipListSet<>();
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
     * Dispatcher hook: announce that a PN has been handed to the encryption pool and a
     * corresponding {@link EncryptedPacket} (or "skipped" placeholder on worker failure)
     * will eventually arrive via {@link #submit}.
     *
     * Called from the dispatcher (single-thread) BEFORE {@code encryptionPool.enqueue}, so the
     * emitter can tell legitimate worker-reorder gaps (PNs that ARE in flight) from wire-level
     * gaps (PNs the dispatcher allocated but never submitted, e.g. assembled-empty results that
     * still burnt a PN via the shared App+ZeroRTT generator). Without this signal the emitter
     * would pay a reorder-wait per burnt PN; on Windows that wait is ~1-3 ms per gap because
     * the JVM timer rounds sub-millisecond sleeps up, which collapses throughput by 50x.
     */
    public void announceSubmitted(long packetNumber) {
        inflightPns.add(packetNumber);
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
                    // Head is ahead of expected. Two reasons this happens:
                    //   1) Wire-level PN gap: dispatcher allocated PNs in (expectedNextPN, head.pn)
                    //      but never submitted them (assemble returned empty after stamping the PN,
                    //      common when App + ZeroRTT share a PN generator). These PNs will never
                    //      arrive; advance immediately.
                    //   2) Worker reorder: a worker is still encrypting some PN < head.pn and will
                    //      submit it shortly. Wait briefly so we emit in order.
                    // Distinguishing case 1 from case 2 with no waste of time: consult inflightPns,
                    // the dispatcher's announce-on-submit set. If no in-flight PN is < head.pn,
                    // the gap is wire-level (case 1) and we skip ahead with zero sleep.
                    Long lowestInflight = inflightPns.isEmpty() ? null : inflightPns.first();
                    if (lowestInflight == null || lowestInflight >= head.getPacketNumber()) {
                        // No worker is producing anything below head.pn; gap is pure wire-level.
                        expectedNextPN = head.getPacketNumber();
                    }
                    else {
                        // Worker reorder: wait briefly for the in-flight low PN to arrive.
                        long deadline = System.nanoTime() + REORDER_TIMEOUT_NANOS;
                        long remainingNanos;
                        while ((remainingNanos = deadline - System.nanoTime()) > 0) {
                            EncryptedPacket peek = queue.peek();
                            if (peek != null && peek.getPacketNumber() <= expectedNextPN) {
                                // Late worker arrived; restart loop, fall into the else branch.
                                break;
                            }
                            long sleepNanos = Math.min(remainingNanos, 10_000L);
                            TimeUnit.NANOSECONDS.sleep(sleepNanos);
                        }
                        head = queue.peek();
                        if (head == null) {
                            continue;
                        }
                        if (head.getPacketNumber() > expectedNextPN) {
                            // Timed out: worker presumably crashed (skipped marker should have arrived
                            // but didn't). Advance past the gap and emit current head.
                            expectedNextPN = head.getPacketNumber();
                        }
                    }
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

                // At this point: head.PN == expectedNextPN (either originally, or after skip).
                emit(head);
                // Math.max guards against a late-arriving worker whose PN is below the current
                // expectedNextPN (which we may have already advanced past via the wire-level gap
                // branch): emit the late packet (it's wire-tolerable reorder) but never let
                // expectedNextPN regress, otherwise the next gap check would see a fake gap.
                expectedNextPN = Math.max(expectedNextPN, head.getPacketNumber() + 1);
                inflightPns.remove(head.getPacketNumber());
                // Trim any inflightPns entries below the new expectedNextPN that were never
                // emitted (e.g. dispatcher announced but the corresponding packet was discarded
                // by the worker on a fatal error and the skip marker raced ahead): keeps the set
                // bounded so lowestInflight stays accurate.
                while (!inflightPns.isEmpty() && inflightPns.first() < expectedNextPN) {
                    inflightPns.pollFirst();
                }
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
