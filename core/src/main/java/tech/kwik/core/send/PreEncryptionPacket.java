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

import tech.kwik.core.ack.AckGenerator;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.packet.QuicPacket;

import java.util.function.Consumer;

/**
 * A QUIC packet body assembled by {@link PacketAssembler#prepareUnencrypted} but not yet
 * assigned a packet number.
 *
 * Returned from {@code prepareUnencrypted} only when the packet is non-empty (frames fit
 * within the available size), so a PN can be safely allocated for it without ever needing
 * to roll back the generator. The pipeline dispatcher allocates the PN and calls
 * {@link #assignPacketNumber}; that stamps the PN onto the packet and, if the packet
 * carries an explicit ACK frame, registers the send with the {@link AckGenerator}.
 *
 * Single-use: once {@link #assignPacketNumber} has been called the underlying packet is
 * ready for encryption and emission; do not reuse the instance.
 */
public class PreEncryptionPacket {

    private final QuicPacket packet;
    private final AckFrame ackFrame;
    private final Consumer<QuicPacket> packetLostCallback;

    /**
     * @param packet              the assembled but PN-less packet
     * @param ackFrame            the explicit ACK frame included in the packet, or null if none; ACK registration is deferred until PN is known
     * @param packetLostCallback  callback to invoke from the recovery manager if the eventual send is detected lost
     */
    public PreEncryptionPacket(QuicPacket packet, AckFrame ackFrame, Consumer<QuicPacket> packetLostCallback) {
        if (packet == null || packetLostCallback == null) {
            throw new IllegalArgumentException();
        }
        this.packet = packet;
        this.ackFrame = ackFrame;
        this.packetLostCallback = packetLostCallback;
    }

    /**
     * Stamps the allocated packet number onto the underlying packet and finalises ACK
     * bookkeeping if this packet carries an explicit ACK frame.
     *
     * Must be called exactly once per instance, by the thread that owns PN allocation
     * (legacy sender thread, or the pipeline dispatcher). After this returns, the packet
     * is ready to be encrypted and emitted.
     *
     * @param packetNumber  PN allocated for this packet from {@link PacketNumberGenerator}
     * @param ackGenerator  the ACK generator to register the send with; may be a no-op if {@code ackFrame} is null
     */
    public void assignPacketNumber(long packetNumber, AckGenerator ackGenerator) {
        packet.setPacketNumber(packetNumber);
        if (ackFrame != null) {
            ackGenerator.registerAckSendWithPacket(ackFrame, packetNumber);
        }
    }

    /**
     * @return the underlying QUIC packet; PN is unset until {@link #assignPacketNumber} is called
     */
    public QuicPacket getPacket() {
        return packet;
    }

    /**
     * @return the packet-lost callback that should accompany the eventual {@link SendItem}
     */
    public Consumer<QuicPacket> getPacketLostCallback() {
        return packetLostCallback;
    }
}
