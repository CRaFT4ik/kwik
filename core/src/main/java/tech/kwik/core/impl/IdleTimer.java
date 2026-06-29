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
package tech.kwik.core.impl;

import tech.kwik.core.Statistics;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.core.log.Logger;
import tech.kwik.core.packet.QuicPacket;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.IntSupplier;

public class IdleTimer {

    private enum Action {
        PACKET_RECEIVED,
        PACKET_SENT
    }
    private final Clock clock;
    private final ScheduledExecutorService timer;
    private final int timerResolution;
    private volatile long timeout;
    private final QuicConnectionImpl connection;
    private final Logger log;
    private volatile IntSupplier ptoSupplier;
    private volatile Instant lastActionTime;
    private volatile boolean enabled;
    private volatile Action lastAction;
    private ScheduledFuture<?> timerTask;


    public IdleTimer(QuicConnectionImpl connection, Logger logger) {
        this(connection, logger, 1000);
    }

    public IdleTimer(QuicConnectionImpl connection, Logger logger, int timerResolution) {
        this(Clock.systemUTC(), connection, logger, timerResolution);
    }

    public IdleTimer(Clock clock, QuicConnectionImpl connection, Logger logger, int timerResolution) {
        this.clock = clock;
        this.connection = connection;
        this.ptoSupplier = () -> 0;
        this.log = logger;
        this.timerResolution = timerResolution;

        timer = createScheduler();
        lastActionTime = clock.instant();
        lastAction = Action.PACKET_RECEIVED;  // Initial state is like a packet was received (no tail loss).
    }

    private ScheduledExecutorService createScheduler() {
        ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1, new DaemonThreadFactory("idle-timer"));
        timer.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        return timer;
    }

    void setIdleTimeout(long idleTimeoutInMillis) {
        timeout = idleTimeoutInMillis;
        if (! enabled) {
            enabled = true;
        }
        else {
            timerTask.cancel(true);
        }
        timerTask = timer.scheduleAtFixedRate(() -> checkIdle(), timerResolution, timerResolution, TimeUnit.MILLISECONDS);
    }

    long getIdleTimeout() {
        return timeout;
    }

    boolean isEnabled() {
        return enabled;
    }

    public void setPtoSupplier(IntSupplier ptoSupplier) {
        this.ptoSupplier = ptoSupplier;
    }

    private void checkIdle() {
        if (enabled) {
            Instant now = clock.instant();
            if (lastActionTime.plusMillis(timeout).isBefore(now)) {
                int currentPto = ptoSupplier.getAsInt();
                // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
                // To avoid excessively small idle timeout periods, endpoints MUST increase the idle timeout period
                // to be at least three times the current Probe Timeout (PTO)
                if (lastActionTime.plusMillis(3L * currentPto).isBefore(now)) {
                    timer.shutdown();
                    // Canary fork: upstream calls silentlyCloseConnection here, which terminates the
                    // connection without emitting a CONNECTION_CLOSE frame. The peer then has to wait
                    // out its own idle timer before it learns the tunnel is gone. Emit an explicit
                    // application-level CC instead so the peer's ConnectionTerminatedEvent fires
                    // immediately with byPeer=true, and log enough state to diagnose why.
                    long ageMs = now.toEpochMilli() - lastActionTime.toEpochMilli();
                    String statsSummary;
                    try {
                        Statistics stats = connection.getStats();
                        statsSummary = String.format(
                                "latestRttMs=%d packetsSent=%d lostPackets=%d",
                                stats.latestRtt(), stats.packetsSent(), stats.lostPackets());
                    }
                    catch (Throwable t) {
                        statsSummary = "stats=n/a";
                    }
                    log.warn(String.format(
                            "idle-timer expired: lastAction=%s ageMs=%d timeoutMs=%d ptoMs=%d %s - closing with CC",
                            lastAction, ageMs, timeout, currentPto, statsSummary));
                    connection.close(0L, "idle-timer-watchdog");
                }
            }}
    }

    public void packetProcessed() {
        if (enabled) {
            // https://tools.ietf.org/html/draft-ietf-quic-transport-31#section-10.1
            // "An endpoint restarts its idle timer when a packet from its peer is received and processed successfully."
            lastActionTime = clock.instant();
            lastAction = Action.PACKET_RECEIVED;
        }
    }

    public void packetSent(QuicPacket packet, Instant sendTime) {
        if (enabled) {
            // RFC 9000 §10.1 says the timer should only restart on an ack-eliciting send when the
            // previous action was a successful receive, to prevent unbounded extension from
            // unanswered sends. In practice that rule breaks keep-alive PINGs over a lossy path:
            // if a single ACK is lost, lastAction stays PACKET_SENT and every subsequent PING is
            // ignored by the timer until an ACK finally lands. With a 30 s idle timeout and 15 s
            // PING cadence, two consecutive lost ACKs are enough to silently close a live tunnel.
            //
            // Canary fork: always restart the timer on an ack-eliciting send. The intent of the
            // RFC rule is preserved by the receiver side - a peer that has gone away cannot ACK,
            // so its own idle timer fires regardless of what we do here. The only behavior change
            // is that a live local endpoint sending PINGs no longer self-evicts under ACK loss.
            if (packet.isAckEliciting()) {
                lastActionTime = sendTime;
                lastAction = Action.PACKET_SENT;
            }
        }
    }

    /**
     * Returns the timestamp of the last action that restarted this timer.
     *
     * The returned instant moves forward on every successfully processed incoming packet and,
     * subject to the RFC 9000 section 10.1 rule, on ack-eliciting sends. Intended for diagnostics
     * such as exporting the time since the last observed peer activity.
     *
     * @return monotonically non-decreasing instant on the configured clock; never null.
     */
    public Instant getLastActionTime() {
        return lastActionTime;
    }

    public void shutdown() {
        if (enabled) {
            timer.shutdown();
        }
    }

    /**
     * Determines if this peer is suffering from tail loss. Tail loss is defined as the situation where the last packets
     * sent by this peer were lost. This may lead to an idle timeout, but this is not an "idle timeout" as most people
     * would understand it (i.e. no network traffic because peers have nothing to say to each other).
     * @return
     */
    public boolean isTailLoss() {
        return lastAction == Action.PACKET_SENT;
    }
}

