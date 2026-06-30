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

import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.packet.QuicPacket;

import java.util.function.Consumer;

/**
 * Encrypted QUIC packet ready to be emitted to the wire, output of an
 * {@link EncryptionWorkerPool} worker and input to the {@link SenderEmitter}.
 *
 * Carries everything the emitter needs to put bytes on the socket and to update
 * recovery / idle-timer / qlog accounting:
 *  - the encrypted datagram bytes;
 *  - the original {@link QuicPacket} (for {@code recoveryManager.packetSent} and
 *    qlog, which want frame-level information);
 *  - the packet number so the emitter can sort and detect gaps;
 *  - the packet-lost callback that travels with the packet through recovery;
 *  - the encryption level (handy for fast-path coalescing decisions).
 *
 * A "skipped" placeholder (no bytes, packet may be null) can also be enqueued by the
 * dispatcher to advance the emitter's expectedNextPN counter when a PN has been
 * allocated but the corresponding assemble produced nothing (e.g. last-moment empty);
 * see {@link #isSkipped()}.
 */
public class EncryptedPacket {

    private final long packetNumber;
    private final byte[] datagramBytes;
    private final QuicPacket packet;
    private final Consumer<QuicPacket> packetLostCallback;
    private final EncryptionLevel level;
    private final boolean skipped;

    /**
     * Real encrypted packet constructor.
     *
     * @param packetNumber        packet number (same as {@code packet.getPacketNumber()})
     * @param datagramBytes       fully encrypted bytes to put on the socket
     * @param packet              source packet, for recovery/qlog accounting
     * @param packetLostCallback  callback to register with the recovery manager
     * @param level               encryption level of the source packet
     */
    public EncryptedPacket(long packetNumber, byte[] datagramBytes, QuicPacket packet,
                           Consumer<QuicPacket> packetLostCallback, EncryptionLevel level) {
        if (datagramBytes == null || packet == null || packetLostCallback == null || level == null) {
            throw new IllegalArgumentException();
        }
        this.packetNumber = packetNumber;
        this.datagramBytes = datagramBytes;
        this.packet = packet;
        this.packetLostCallback = packetLostCallback;
        this.level = level;
        this.skipped = false;
    }

    private EncryptedPacket(long packetNumber) {
        this.packetNumber = packetNumber;
        this.datagramBytes = null;
        this.packet = null;
        this.packetLostCallback = null;
        this.level = null;
        this.skipped = true;
    }

    /**
     * Creates a placeholder that advances the emitter's expectedNextPN by one without
     * actually emitting anything. Used by the dispatcher when a PN is allocated but the
     * worker chain decides not to produce a real packet (skipping should be rare, but
     * the pipeline must tolerate it without stalling the emitter).
     *
     * @param packetNumber  the PN to mark as skipped
     */
    public static EncryptedPacket skipped(long packetNumber) {
        return new EncryptedPacket(packetNumber);
    }

    public long getPacketNumber() {
        return packetNumber;
    }

    public byte[] getDatagramBytes() {
        return datagramBytes;
    }

    public QuicPacket getPacket() {
        return packet;
    }

    public Consumer<QuicPacket> getPacketLostCallback() {
        return packetLostCallback;
    }

    public EncryptionLevel getLevel() {
        return level;
    }

    public boolean isSkipped() {
        return skipped;
    }
}
