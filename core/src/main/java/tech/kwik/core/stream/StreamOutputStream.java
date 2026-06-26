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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public abstract class StreamOutputStream extends OutputStream {

    abstract void reset(long errorCode);

    protected abstract void resetOutputStream();

    protected abstract void stopFlowControl();

    abstract void abort();

    /**
     * Offers as many bytes from {@code src} as fit into the stream's send buffer immediately,
     * without blocking. Returns the number of bytes consumed (which may be {@code 0} when the
     * buffer is full; the caller then waits for
     * {@link StreamWriteListener#onWritable(tech.kwik.core.QuicStream)} and retries).
     * <p>
     * When the returned value is positive, the source buffer's position has advanced by that many
     * bytes (mirroring channel/buffer write semantics).
     * <p>
     * Equivalent to a single non-blocking {@code write} call: never sleeps, never waits on a
     * monitor, never throws on a full buffer. Throws {@link IOException} only on terminal states
     * (stream closed locally, reset locally, or aborted because the connection died).
     *
     * @param src source buffer; bytes are read starting at its current position and the position
     *            is advanced by the number of bytes accepted.
     * @return bytes consumed from {@code src} (0 when the send buffer is currently full).
     * @throws IOException if the stream is no longer accepting writes.
     */
    public abstract int writeAvailable(ByteBuffer src) throws IOException;
}
