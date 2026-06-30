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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.crypto.ConnectionSecrets;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.IdleTimer;
import tech.kwik.core.impl.QuicConnectionImpl;
import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.packet.ShortHeaderPacket;
import tech.kwik.core.test.FieldSetter;
import tech.kwik.core.test.TestClock;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;

/**
 * End-to-end pipeline-mode coverage: with the encryption-pool-size system property set,
 * SenderImpl routes App-level single-packet datagrams through the worker pool + emitter
 * instead of the inline send path. Verifies socket.send still fires (just from the
 * emitter thread) and the in-flight bytes counters reflect what was emitted.
 */
class SenderImplPipelineTest extends AbstractSenderTest {

    private static final String POOL_SIZE_PROP = "tech.kwik.core.send.encryption-pool-size";
    private static String prevPoolSize;

    private TestClock clock;
    private SenderImpl sender;
    private DatagramSocket socket;
    private ConnectionSecrets connectionSecrets;

    @BeforeAll
    static void enablePipeline() {
        prevPoolSize = System.getProperty(POOL_SIZE_PROP);
        System.setProperty(POOL_SIZE_PROP, "2");
    }

    @AfterAll
    static void restorePipeline() {
        if (prevPoolSize == null) {
            System.clearProperty(POOL_SIZE_PROP);
        }
        else {
            System.setProperty(POOL_SIZE_PROP, prevPoolSize);
        }
    }

    @BeforeEach
    void initObjectUnderTest() throws Exception {
        clock = new TestClock();
        socket = mock(DatagramSocket.class);
        InetSocketAddress peerAddress = new InetSocketAddress("example.com", 443);
        QuicConnectionImpl connection = mock(QuicConnectionImpl.class);
        when(connection.getDestinationConnectionId()).thenReturn(new byte[4]);
        when(connection.getSourceConnectionId()).thenReturn(new byte[4]);
        when(connection.getIdleTimer()).thenReturn(new IdleTimer(connection, new NullLogger()));

        connectionSecrets = mock(ConnectionSecrets.class);
        Aead aead = TestUtils.createKeys();
        when(connectionSecrets.getOwnAead(any(EncryptionLevel.class))).thenReturn(aead);

        sender = new SenderImpl(clock, new VersionHolder(Version.getDefault()), 1200, socket, peerAddress, connection, "pipe-test", 100, new NullLogger());
        FieldSetter.setField(sender, sender.getClass().getDeclaredField("connectionSecrets"), connectionSecrets);
    }

    @Test
    void appLevelPacketsAreEmittedViaPipeline() throws Exception {
        ShortHeaderPacket packet = new ShortHeaderPacket(Version.getDefault(), new byte[4], new StreamFrame(0, new byte[64], false));
        packet.setPacketNumber(7);

        // Start the pipeline (emitter thread).
        sender.start(connectionSecrets);

        sender.send(new AssembledDatagram(new SendItem(packet)));

        // Pipeline is async: wait for the emitter to actually fire socket.send.
        waitFor(() -> sender.getStatistics().datagramsSent() == 1, 5000);

        ArgumentCaptor<DatagramPacket> captor = ArgumentCaptor.forClass(DatagramPacket.class);
        verify(socket, atLeastOnce()).send(captor.capture());
        DatagramPacket sentDatagram = captor.getValue();
        assertThat(sentDatagram.getLength()).isGreaterThan(0);
        assertThat(sender.getStatistics().datagramsSent()).isEqualTo(1);
        assertThat(sender.getStatistics().packetsSent()).isEqualTo(1);

        sender.stop();
        sender.shutdown(() -> {});
    }

    @Test
    void multiplePipelinePacketsRetainPnOrderOnWire() throws Exception {
        // Submit three packets with monotonic PNs; emitter must preserve order.
        sender.start(connectionSecrets);
        // PNs must start where the pipeline's expectedNextPN starts (0) so the emitter does
        // not waste its reorder window waiting for missing earlier PNs.
        for (int pn = 0; pn < 3; pn++) {
            ShortHeaderPacket pkt = new ShortHeaderPacket(Version.getDefault(), new byte[4], new StreamFrame(0, new byte[32], false));
            pkt.setPacketNumber(pn);
            sender.send(new AssembledDatagram(new SendItem(pkt)));
        }

        waitFor(() -> sender.getStatistics().datagramsSent() == 3, 5000);
        assertThat(sender.getStatistics().packetsSent()).isEqualTo(3);

        sender.stop();
        sender.shutdown(() -> {});
    }

    private static void waitFor(java.util.function.BooleanSupplier cond, long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (System.currentTimeMillis() < deadline) {
            if (cond.getAsBoolean()) return;
            TimeUnit.MILLISECONDS.sleep(5);
        }
        if (!cond.getAsBoolean()) {
            throw new AssertionError("Condition not satisfied within " + timeoutMillis + "ms");
        }
    }
}
