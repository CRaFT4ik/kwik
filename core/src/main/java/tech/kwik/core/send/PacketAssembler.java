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
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.frame.AckFrame;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.packet.HandshakePacket;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.packet.ZeroRttPacket;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import static tech.kwik.core.common.EncryptionLevel.App;

/**
 * Assembles QUIC packets for a given encryption level, based on "send requests" that are previously queued.
 * These send requests either contain a frame, or can produce a frame to be sent.
 *
 * Allocates a packet number only after the assembled packet is known to be non-empty, so
 * the underlying {@link PacketNumberGenerator} never has to roll back. This contract is what
 * lets the upcoming multi-thread sender pipeline drive assembly from a dispatcher and
 * encryption from a worker pool without racing on the PN counter.
 */
public class PacketAssembler {

    protected final static Consumer<QuicFrame> EMPTY_CALLBACK = f -> {};

    protected final VersionHolder quicVersion;
    protected final EncryptionLevel level;
    protected final SendRequestQueue requestQueue;
    protected final AckGenerator ackGenerator;
    private final PacketNumberGenerator packetNumberGenerator;
    protected long nextPacketNumber;
    private volatile boolean stopping;
    private Consumer<PacketAssembler> finalizerCallback;


    public PacketAssembler(VersionHolder version, EncryptionLevel level, SendRequestQueue requestQueue, AckGenerator ackGenerator) {
        this(version, level, requestQueue, ackGenerator, new PacketNumberGenerator());
    }

    public PacketAssembler(VersionHolder version, EncryptionLevel level, SendRequestQueue requestQueue, AckGenerator ackGenerator, PacketNumberGenerator pnGenerator) {
        quicVersion = version;
        this.level = level;
        this.requestQueue = requestQueue;
        this.ackGenerator = ackGenerator;
        packetNumberGenerator = pnGenerator;
    }

    /**
     * Assembles a QUIC packet for the encryption level handled by this instance and assigns a
     * packet number to it.
     *
     * Thin compatibility wrapper around {@link #prepareUnencrypted}: on a non-empty result it
     * allocates a fresh PN via {@link PacketNumberGenerator#nextPacketNumber()}, stamps it onto
     * the packet, and registers any included ACK frame with the {@link AckGenerator}. Used by
     * the single-thread sender path (legacy mode, {@code encryption-pool-size=0}); the pipeline
     * dispatcher calls {@link #prepareUnencrypted} directly so it can sequence PN allocation
     * against the encryption queue.
     *
     * @param remainingCwndSize         soft upper bound on packet size from the congestion controller
     * @param availablePacketSize       hard upper bound on packet size from datagram/MTU budget
     * @param sourceConnectionId        may be null at App level, must be non-null at other levels (empty array allowed)
     * @param destinationConnectionId   peer connection id to address the packet to
     * @return assembled packet with PN assigned, or empty if no frames fit
     */
    Optional<SendItem> assemble(int remainingCwndSize, int availablePacketSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        Optional<PreEncryptionPacket> prepared = prepareUnencrypted(remainingCwndSize, availablePacketSize, sourceConnectionId, destinationConnectionId);
        if (prepared.isEmpty()) {
            return Optional.empty();
        }
        PreEncryptionPacket pre = prepared.get();
        long pn = packetNumberGenerator.nextPacketNumber();
        pre.assignPacketNumber(pn, ackGenerator);
        return Optional.of(new SendItem(pre.getPacket(), pre.getPacketLostCallback()));
    }

    /**
     * Assembles a packet body (frames + optional ACK) for this encryption level without
     * allocating or stamping a packet number.
     *
     * Pulls send requests, the explicit ACK, and probe data exactly as {@link #assemble} does,
     * but stops short of touching {@link PacketNumberGenerator}. The returned
     * {@link PreEncryptionPacket} carries a callback that the caller must invoke once a PN has
     * been allocated; that callback stamps the PN onto the packet and registers any embedded
     * ACK with the {@link AckGenerator}. This split lets the pipeline dispatcher allocate PN
     * only after assembly is known to have produced frames, so allocations are always consumed.
     *
     * @param remainingCwndSize         soft upper bound on packet size from the congestion controller
     * @param availablePacketSize       hard upper bound on packet size from datagram/MTU budget
     * @param sourceConnectionId        may be null at App level, must be non-null at other levels (empty array allowed)
     * @param destinationConnectionId   peer connection id to address the packet to
     * @return a non-empty unencrypted packet awaiting PN, or empty when no frames fit
     */
    Optional<PreEncryptionPacket> prepareUnencrypted(int remainingCwndSize, int availablePacketSize, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        final int available = Integer.min(remainingCwndSize, availablePacketSize);

        QuicPacket packet = createPacket(sourceConnectionId, destinationConnectionId);
        List<Consumer<QuicFrame>> callbacks = new ArrayList<>();

        AckFrame ackFrame = null;
        // Check for an explicit ack, i.e. an ack on ack-eliciting packet that cannot be delayed (any longer).
        // ACK frame is recorded here but registered with AckGenerator only after PN is allocated (see PreEncryptionPacket.assignPacketNumber).
        if (requestQueue.mustAndWillSendAck()) {
            if (ackGenerator.hasNewAckToSend()) {
                ackFrame = ackGenerator.generateAck().get();   // Explicit ack cannot disappear by other means than sending it.
                // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-13.2
                // "... packets containing only ACK frames are not congestion controlled ..."
                // So: only check if it fits within available packet space
                if (packet.estimateLength(ackFrame.getFrameLength()) <= availablePacketSize) {
                    packet.addFrame(ackFrame);
                    callbacks.add(EMPTY_CALLBACK);
                }
                else {
                    // If not even a mandatory ack can be added, don't bother about other frames: theoretically there might be frames
                    // that can be fit, but this is very unlikely to happen (because limit packet size is caused by coalescing packets
                    // in one datagram, which will only happen during handshake, when acks are still small) and even then: there
                    // will be a next packet in due time.
                    // However, the ack removed from the queue must be returned
                    requestQueue.addAckRequest();
                    return Optional.empty();
                }
            }
        }

        if (requestQueue.hasProbeWithData()) {
            List<QuicFrame> probeData = requestQueue.getProbe();
            // Probe is not limited by congestion control, but it is limited by max packet size.
            int estimatedSize = packet.estimateLength(probeData.stream().mapToInt(f -> f.getFrameLength()).sum());
            if (estimatedSize > availablePacketSize) {
                QuicFrame probeFrame = new PingFrame();
                if (packet.estimateLength(probeFrame.getFrameLength()) > availablePacketSize) {
                    return Optional.empty();
                }
                probeData = List.of(probeFrame);
            }
            packet.setIsProbe(true);
            packet.addFrames(probeData);
            return Optional.of(new PreEncryptionPacket(packet, ackFrame, SendItem.EMPTY_CALLBACK));
        }

        if (requestQueue.hasRequests()) {
            // Must create packet here, to have an initial estimate of packet header overhead
            int estimatedSize = packet.estimateLength(1000) - 1000;  // Estimate length if large frame would have been added; this will give upper limit of packet overhead.

            while (estimatedSize < available) {
                int proposedSize = available - estimatedSize;
                Optional<SendRequest> next = requestQueue.next(proposedSize);
                if (next.isEmpty()) {
                    // Nothing fits within available space
                    break;
                }
                QuicFrame nextFrame = next.get().getFrame(proposedSize);
                if (nextFrame != null) {
                    if (nextFrame.getFrameLength() > proposedSize) {
                        throw new RuntimeException("supplier does not produce frame of right (max) size: " + nextFrame.getFrameLength() + " > " + (proposedSize) + " frame: " + nextFrame);
                    }

                    estimatedSize += nextFrame.getFrameLength();
                    packet.addFrame(nextFrame);
                    callbacks.add(next.get().getLostCallback());
                }
            }
        }

        if (requestQueue.hasProbe() && packet.getFrames().isEmpty()) {
            requestQueue.getProbe();
            packet.setIsProbe(true);
            packet.addFrame(new PingFrame());
            callbacks.add(EMPTY_CALLBACK);
        }

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2.4
        // "A receiver that sends only non-ack-eliciting packets, such as ACK frames, might not receive an acknowledgment
        //  for a long period of time. (...) In such a case, a receiver could send a PING (...) to elicit an ACK from the peer."
        if (packet.isAckOnly() && level == App) {
            if (ackGenerator.wantsAckFromPeer()) {
                packet.addFrame(new PingFrame());
                callbacks.add(EMPTY_CALLBACK);
            }
        }
        Optional<PreEncryptionPacket> prepared;
        if (packet.getFrames().isEmpty()) {
            // Nothing fit; do not allocate a PN so the counter stays gap-free for the dispatcher.
            prepared = Optional.empty();
        }
        else {
            prepared = Optional.of(new PreEncryptionPacket(packet, ackFrame, createPacketLostCallback(packet, callbacks)));
        }

        if (stopping && requestQueue.isEmpty(false)) {
            if (finalizerCallback != null) {
                finalizerCallback.accept(this);
            }
        }

        return prepared;
    }

    protected long nextPacketNumber() {
        return packetNumberGenerator.nextPacketNumber();
    }

    private Consumer<QuicPacket> createPacketLostCallback(QuicPacket packet, List<Consumer<QuicFrame>> callbacks) {
        if (packet.getFrames().size() != callbacks.size()) {
            throw new IllegalStateException();
        }
        return lostPacket -> {
            for (int i = 0; i < callbacks.size(); i++) {
                if (callbacks.get(i) != EMPTY_CALLBACK) {
                    QuicFrame lostFrame = lostPacket.getFrames().get(i);
                    callbacks.get(i).accept(lostFrame);
                }
            }
        };
    }

    protected QuicPacket createPacket(byte[] sourceConnectionId, byte[] destinationConnectionId) {
        QuicPacket packet;
        switch (level) {
            case Handshake:
                packet = new HandshakePacket(quicVersion.getVersion(), sourceConnectionId, destinationConnectionId, null);
                break;
            case App:
                packet = new ShortHeaderPacket(quicVersion.getVersion(), destinationConnectionId, null);
                break;
            case ZeroRTT:
                packet = new ZeroRttPacket(quicVersion.getVersion(), sourceConnectionId, destinationConnectionId, (QuicFrame) null);
                break;
            default:
                throw new RuntimeException();  // programming error
        }
        // Provisional PN=0 only for estimateLength sizing during assembly; the real PN is stamped
        // by PreEncryptionPacket.assignPacketNumber once the packet is known non-empty. Using 0
        // (1-byte encoded) keeps assembly sizing consistent with the legacy behaviour where PN
        // was assigned eagerly from the start of the connection.
        packet.setPacketNumber(0);
        return packet;
    }

    public void stop(Consumer<PacketAssembler> finalizer) {
        this.finalizerCallback = finalizer;
        requestQueue.clear(false);
        stopping = true;
    }

    @Override
    public String toString() {
        return "PacketAssembler[" + level + "]";
    }
}

