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
 * Optional, non-blocking signal sink for a {@link QuicStream}'s send side.
 * <p>
 * Registered via {@link QuicStream#setWriteListener(StreamWriteListener)}. Once attached, the kwik
 * sender path invokes the appropriate callback whenever space frees up in the stream's send buffer
 * (so a caller that previously could not buffer all of its bytes may try again), or when the send
 * side terminates. The application then offers bytes with
 * {@link StreamOutputStream#writeAvailable(java.nio.ByteBuffer)} which never blocks; if the buffer
 * is full the call returns 0 and the caller waits for the next {@link #onWritable} notification.
 * <p>
 * <b>Threading contract: every callback MUST be non-blocking and O(1).</b> Callbacks are invoked
 * from the connection's sender path (the same thread that drains the send buffer into packets); any
 * blocking or long-running work inside the callback stalls every other stream on the same
 * connection. A typical implementation just signals a coroutine / selector / executor and returns
 * immediately. Implementations MUST NOT throw - the sender path swallows exceptions defensively,
 * but a thrown exception still indicates a bug in the listener.
 */
public interface StreamWriteListener {

    /**
     * Invoked when bytes drained out of the stream's send buffer and additional buffer space is
     * now available.
     * <p>
     * The signal is edge-triggered and may be coalesced: a single callback can cover an arbitrary
     * amount of freed space. The listener is responsible for retrying
     * {@link StreamOutputStream#writeAvailable(java.nio.ByteBuffer)} until it returns 0 again.
     * MUST NOT block.
     *
     * @param stream the stream whose send buffer just freed space.
     */
    void onWritable(QuicStream stream);

    /**
     * Invoked exactly once when the send side terminates (clean close after the final frame, local
     * reset, or peer-side abort that affects the send half). After this callback the stream
     * produces no more write events. MUST NOT block.
     *
     * @param stream the stream whose send side closed.
     */
    void onWriteClosed(QuicStream stream);

    /**
     * Invoked exactly once when the local side issued RESET_STREAM. After this callback no more
     * write events fire and {@link StreamOutputStream#writeAvailable(java.nio.ByteBuffer)} will
     * throw. MUST NOT block.
     *
     * @param stream    the reset stream.
     * @param errorCode the application-protocol error code carried in the RESET_STREAM frame.
     */
    void onWriteReset(QuicStream stream, long errorCode);
}
