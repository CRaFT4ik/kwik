/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.stream;

import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.TransportError;

import java.io.InputStream;

public abstract class StreamInputStream extends InputStream {

    abstract long addDataFrom(StreamFrame frame) throws TransportError;

    abstract long getCurrentReceiveOffset();

    abstract void abortReading(long applicationProtocolErrorCode);

    abstract long terminate(long errorCode, long finalSize) throws TransportError;

    abstract void abort();

    /**
     * Drains any bytes immediately available in the receive buffer into {@code dst} without
     * blocking, and updates flow-control credit identically to the blocking
     * {@link #read(byte[], int, int)} path.
     * <p>
     * Returns the number of bytes copied (always {@code > 0} when there were any), {@code 0} if
     * the buffer was empty but the stream is still live (more data may arrive later), or
     * {@code -1} if the receive side has reached clean EOF and no more bytes will ever arrive.
     * Equivalent to a single non-blocking {@code read} call: never sleeps, never waits on a
     * monitor, never throws on an empty buffer.
     *
     * @param dst destination buffer; bytes are written starting at its current position and the
     *            position is advanced by the number of bytes copied.
     * @return bytes copied; 0 when no bytes are buffered; -1 on clean EOF.
     * @throws java.io.IOException if the stream was locally closed/aborted or reset by the peer.
     */
    public abstract int readAvailable(java.nio.ByteBuffer dst) throws java.io.IOException;
}
