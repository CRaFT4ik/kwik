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

import java.util.concurrent.atomic.AtomicLong;

/**
 * Monotonic packet number source for a single QUIC packet-number space.
 *
 * Thread-safe: {@link #nextPacketNumber()} is backed by an {@link AtomicLong} and may
 * be called from any thread. Numbers handed out are strictly increasing, with no
 * gaps when callers consume each number they request.
 *
 * Multi-thread pipeline mode allocates packet numbers from the dispatcher thread only
 * after a packet is known to be non-empty, so there is never a need to "give back"
 * a previously allocated number; the legacy single-thread restore API has been removed
 * to make this invariant explicit.
 */
public class PacketNumberGenerator {

    private final AtomicLong packetNumber = new AtomicLong();

    /**
     * Allocates the next packet number for this PN space.
     *
     * @return the next monotonic packet number, starting at 0 on a fresh generator
     */
    public long nextPacketNumber() {
        return packetNumber.getAndIncrement();
    }
}
