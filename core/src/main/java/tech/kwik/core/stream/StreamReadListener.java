/*
 * Copyright © 2026 Peter Doornbosch
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

import tech.kwik.core.QuicStream;

/**
 * Optional, non-blocking signal sink for a {@link QuicStream}'s receive side.
 * <p>
 * Registered via {@link QuicStream#setReadListener(StreamReadListener)}. Once attached, the kwik
 * receive loop invokes the appropriate callback whenever the stream's receive state changes; the
 * application then drains buffered bytes with {@link StreamInputStream#readAvailable(java.nio.ByteBuffer)}
 * without ever blocking a thread on a synchronous {@link java.io.InputStream#read} call.
 * <p>
 * <b>Threading contract: every callback MUST be non-blocking and O(1).</b> It is invoked from the
 * connection's receive loop; any blocking or long-running work inside the callback stalls every
 * other stream on the same connection. A typical implementation just signals a coroutine /
 * selector / executor and returns immediately. Implementations MUST NOT throw - the receive loop
 * swallows exceptions defensively, but a thrown exception still indicates a bug in the listener.
 */
public interface StreamReadListener {

    /**
     * Invoked when one or more new bytes have been added to the stream's receive buffer.
     * <p>
     * Fired after the bytes are queryable via {@link StreamInputStream#readAvailable(java.nio.ByteBuffer)}
     * / {@link java.io.InputStream#available()}. May be coalesced: the listener is responsible for
     * draining the buffer in a loop until {@code readAvailable} returns 0. MUST NOT block.
     *
     * @param stream the stream whose receive buffer now holds bytes.
     */
    void onDataAvailable(QuicStream stream);

    /**
     * Invoked exactly once when the peer aborted the sending side with a RESET_STREAM frame.
     * <p>
     * After this callback fires the stream has no more data and {@code readAvailable} will return
     * {@code -1}. MUST NOT block.
     *
     * @param stream    the reset stream.
     * @param errorCode the application-protocol error code carried in the RESET_STREAM frame.
     */
    void onReset(QuicStream stream, long errorCode);

    /**
     * Invoked exactly once when the receive side is closed (clean EOF, local
     * {@link QuicStream#abortReading(long)}, or after {@link #onReset}). After this callback the
     * stream produces no more events. MUST NOT block.
     *
     * @param stream the closed stream.
     */
    void onClosed(QuicStream stream);
}
