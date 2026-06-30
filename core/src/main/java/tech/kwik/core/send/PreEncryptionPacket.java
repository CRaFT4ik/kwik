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
 * A QUIC packet body assembled by {@link PacketAssembler#prepareUnencrypted}, with its
 * packet number already stamped (consumed from the {@link PacketNumberGenerator} inside
 * {@code createPacket}) but ACK-frame registration with the {@link AckGenerator} still
 * pending.
 *
 * Deferring ACK registration to {@link #finalizeForSend} keeps the side effect on the
 * assembler/dispatcher thread (the thread that produced the PN), so the ACK is registered
 * exactly once per packet and in PN-allocation order. Empty assembles never produce a
 * PreEncryptionPacket, so a non-empty packet always backs every consumed PN; an empty
 * assemble simply leaves a wire-level gap, which QUIC tolerates.
 *
 * Single-use: once {@link #finalizeForSend} has been called the underlying packet is ready
 * for encryption and emission; do not reuse the instance.
 */
public class PreEncryptionPacket {

    private final QuicPacket packet;
    private final AckFrame ackFrame;
    private final Consumer<QuicPacket> packetLostCallback;

    /**
     * @param packet              the assembled packet; PN already stamped via {@code packet.setPacketNumber} in {@link PacketAssembler#createPacket}
     * @param ackFrame            the explicit ACK frame included in the packet, or null if none; ACK registration is deferred until {@link #finalizeForSend}
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
     * Finalises this packet for downstream encryption + emission: if it carries an explicit
     * ACK frame, registers the send with the supplied {@link AckGenerator}; otherwise a no-op.
     *
     * Must be called exactly once per instance, on the same thread that produced the packet
     * (legacy sender thread, or the pipeline dispatcher). After this returns, the packet
     * is ready to be encrypted and emitted.
     *
     * @param ackGenerator  the ACK generator to register the send with; ignored if {@code ackFrame} is null
     */
    public void finalizeForSend(AckGenerator ackGenerator) {
        if (ackFrame != null) {
            ackGenerator.registerAckSendWithPacket(ackFrame, packet.getPacketNumber());
        }
    }

    /**
     * @return the underlying QUIC packet with its PN already stamped
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
