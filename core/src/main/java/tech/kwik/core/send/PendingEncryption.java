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
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.packet.QuicPacket;

import java.util.function.Consumer;

/**
 * Unit of work enqueued by the pipeline dispatcher into the {@link EncryptionWorkerPool}.
 *
 * Carries a fully assembled QUIC packet (PN already stamped) along with everything an
 * encryption worker needs to turn it into wire bytes: the {@link Aead} for the packet's
 * encryption level and the packet-lost callback that must travel with the resulting
 * {@link EncryptedPacket}. The PN is also carried explicitly so the emitter can order
 * encrypted packets on the way out without re-reading the packet object.
 *
 * Immutable; produced by the dispatcher, consumed by exactly one worker.
 */
public class PendingEncryption {

    private final QuicPacket packet;
    private final long packetNumber;
    private final EncryptionLevel level;
    private final Aead aead;
    private final Consumer<QuicPacket> packetLostCallback;

    /**
     * @param packet              assembled packet with its PN already stamped
     * @param packetNumber        packet number for this packet (must match {@code packet.getPacketNumber()})
     * @param level               encryption level the packet was assembled at
     * @param aead                AEAD for {@code level}; encryption workers may share this instance, so it must be thread-safe
     * @param packetLostCallback  callback to attach to the recovery manager once the packet is emitted
     */
    public PendingEncryption(QuicPacket packet, long packetNumber, EncryptionLevel level, Aead aead,
                             Consumer<QuicPacket> packetLostCallback) {
        if (packet == null || level == null || aead == null || packetLostCallback == null) {
            throw new IllegalArgumentException();
        }
        this.packet = packet;
        this.packetNumber = packetNumber;
        this.level = level;
        this.aead = aead;
        this.packetLostCallback = packetLostCallback;
    }

    public QuicPacket getPacket() {
        return packet;
    }

    public long getPacketNumber() {
        return packetNumber;
    }

    public EncryptionLevel getLevel() {
        return level;
    }

    public Aead getAead() {
        return aead;
    }

    public Consumer<QuicPacket> getPacketLostCallback() {
        return packetLostCallback;
    }
}
