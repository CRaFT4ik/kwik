/*
 * Copyright © 2024, 2025, 2026 Peter Doornbosch
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
import tech.kwik.core.impl.Version;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Buffer for data to be sent on a stream. The buffer has a maximum size, and writing to it will block if the buffer is
 * full. The buffer is thread-safe for concurrent writes and reads, not for concurrent writes or concurrent reads.
 */
public class SendBuffer {

    // Send queue contains stream bytes to send in order. The position of the first byte buffer in the queue determines the next byte(s) to send.
    private final Queue<ByteBuffer> sendQueue;
    private final ByteBuffer END_OF_STREAM_MARKER = ByteBuffer.allocate(0);
    private final int maxBufferSize;
    private final AtomicInteger bufferedBytes;
    private final ReentrantLock bufferLock;
    private final Condition notFull;
    private volatile Thread blockingWriterThread;


    public SendBuffer(Integer sendBufferSize) {
        sendQueue = new ConcurrentLinkedDeque<>();
        if (sendBufferSize != null && sendBufferSize > 0) {
            maxBufferSize = sendBufferSize;
        }
        else {
            maxBufferSize = 50 * 1024;
        }
        bufferedBytes = new AtomicInteger();
        bufferLock = new ReentrantLock();
        notFull = bufferLock.newCondition();
    }

    /**
     * Writes data to the buffer. If the buffer is full, the method will block until there is enough space in the buffer.
     * This method makes defensive copies of the data.
     * @param data
     * @param off
     * @param len
     * @throws IOException
     * @throws InterruptedException
     */
    public void write(byte[] data, int off, int len) throws IOException, InterruptedException {
        int availableBufferSpace = maxBufferSize - bufferedBytes.get();
        if (len > availableBufferSpace) {
            // Wait for enough buffer space to become available
            bufferLock.lock();
            blockingWriterThread = Thread.currentThread();
            try {
                while (maxBufferSize - bufferedBytes.get() < len) {
                    if (Thread.currentThread().isInterrupted()) {
                        throw new InterruptedException();
                    }
                    // Might throw InterruptedException, must be handled by caller
                    notFull.await();
                }
            }
            finally {
                blockingWriterThread = null;
                bufferLock.unlock();
            }
        }

        sendQueue.add(ByteBuffer.wrap(Arrays.copyOfRange(data, off, off + len)));
        bufferedBytes.getAndAdd(len);
    }

    public StreamFrame getStreamFrame(Version quicVersion, int streamId, long currentOffset, int maxBytesToSend) {
        int nrOfBytes = 0;
        byte[] dataToSend = new byte[maxBytesToSend];
        boolean finalFrame = false;
        while (nrOfBytes < maxBytesToSend && !sendQueue.isEmpty()) {
            ByteBuffer buffer = sendQueue.peek();
            int position = nrOfBytes;
            if (buffer.remaining() <= maxBytesToSend - nrOfBytes) {
                // All bytes remaining in buffer will fit in stream frame
                nrOfBytes += buffer.remaining();
                buffer.get(dataToSend, position, buffer.remaining());
                sendQueue.poll();
            }
            else {
                // Just part of the buffer will fit in (and will fill up) the stream frame
                buffer.get(dataToSend, position, maxBytesToSend - nrOfBytes);
                nrOfBytes = maxBytesToSend;  // Short form of: nrOfBytes += (maxBytesToSend - nrOfBytes)
            }
        }

        if (!sendQueue.isEmpty() && sendQueue.peek() == END_OF_STREAM_MARKER) {
            finalFrame = true;
            sendQueue.poll();
        }
        if (nrOfBytes == 0 && !finalFrame) {
            // Nothing to send really
            return null;
        }

        bufferedBytes.getAndAdd(-1 * nrOfBytes);
        bufferLock.lock();
        try {
            notFull.signal();
        }
        finally {
            bufferLock.unlock();
        }
        if (nrOfBytes < maxBytesToSend) {
            // This can happen when not enough data is buffer to fill a stream frame, or length field is 1 byte (instead of 2 that was counted for)
            dataToSend = Arrays.copyOfRange(dataToSend, 0, nrOfBytes);
        }
        StreamFrame streamFrame = new StreamFrame(quicVersion, streamId, currentOffset, dataToSend, finalFrame);
        return streamFrame;
    }

    /**
     * Offers as many bytes from {@code src} as fit into the buffer immediately, without blocking.
     * <p>
     * Returns the number of bytes consumed (which may be {@code 0} when the buffer is full).
     * Mirrors the blocking {@link #write(byte[], int, int)} path except that it never waits on
     * {@link #notFull}: callers that get less than they wanted register for the
     * {@link StreamWriteListener#onWritable(tech.kwik.core.QuicStream)} signal and retry.
     *
     * @param src source buffer; bytes are consumed starting at its current position and the
     *            position is advanced by the number of bytes accepted.
     * @return bytes consumed from {@code src} (0 when the buffer is currently full).
     */
    public int writeAvailable(ByteBuffer src) {
        int wanted = src.remaining();
        if (wanted == 0) {
            return 0;
        }
        int availableBufferSpace = maxBufferSize - bufferedBytes.get();
        if (availableBufferSpace <= 0) {
            return 0;
        }
        int toAccept = Math.min(wanted, availableBufferSpace);
        byte[] copy = new byte[toAccept];
        src.get(copy);
        sendQueue.add(ByteBuffer.wrap(copy));
        bufferedBytes.getAndAdd(toAccept);
        return toAccept;
    }

    public int getAvailableBytes() {
        return bufferedBytes.get();
    }

    public boolean isEmpty() {
        return sendQueue.isEmpty();
    }

    public void close() {
        sendQueue.add(END_OF_STREAM_MARKER);
    }

    public void clear() {
        sendQueue.clear();
        bufferedBytes.set(0);
    }

    public void interruptBlockedWriter() {
        Thread blocking = blockingWriterThread;
        if (blocking != null) {
            blocking.interrupt();
        }
    }

    public int getMaxSize() {
        return maxBufferSize;
    }

    public boolean hasData() {
        return !sendQueue.isEmpty();
    }
}
