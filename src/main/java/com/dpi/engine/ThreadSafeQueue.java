package com.dpi.engine;

import java.util.LinkedList;
import java.util.Queue;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * ThreadSafeQueue - A thread-safe bounded blocking queue with shutdown support,
 * matching the behavior of the C++ ThreadSafeQueue.
 */
public class ThreadSafeQueue<T> {
    private final Queue<T> queue = new LinkedList<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private final int maxSize;
    private boolean shutdown = false;

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    public ThreadSafeQueue() {
        this(10000);
    }

    /**
     * Push item to queue. Blocks if queue is full.
     */
    public void push(T item) {
        lock.lock();
        try {
            while (queue.size() >= maxSize && !shutdown) {
                notFull.await();
            }
            if (shutdown) {
                return;
            }
            queue.offer(item);
            notEmpty.signal();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Try to push item immediately. Returns false if full or shut down.
     */
    public boolean tryPush(T item) {
        lock.lock();
        try {
            if (queue.size() >= maxSize || shutdown) {
                return false;
            }
            queue.offer(item);
            notEmpty.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Pop item from queue. Blocks if empty. Returns empty optional if shutdown.
     */
    public Optional<T> pop() {
        lock.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                notEmpty.await();
            }
            if (queue.isEmpty()) {
                return Optional.empty();
            }
            T item = queue.poll();
            notFull.signal();
            return Optional.ofNullable(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Pop item with timeout. Returns empty optional if timed out or shutdown.
     */
    public Optional<T> popWithTimeout(long timeoutMs) {
        lock.lock();
        try {
            long remainingNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs);
            while (queue.isEmpty() && !shutdown) {
                if (remainingNanos <= 0) {
                    return Optional.empty(); // Timeout
                }
                remainingNanos = notEmpty.awaitNanos(remainingNanos);
            }
            if (queue.isEmpty()) {
                return Optional.empty();
            }
            T item = queue.poll();
            notFull.signal();
            return Optional.ofNullable(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    public boolean isEmpty() {
        lock.lock();
        try {
            return queue.isEmpty();
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return queue.size();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Shut down the queue and wake up all waiting threads.
     */
    public void shutdown() {
        lock.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public boolean isShutdown() {
        lock.lock();
        try {
            return shutdown;
        } finally {
            lock.unlock();
        }
    }
}
