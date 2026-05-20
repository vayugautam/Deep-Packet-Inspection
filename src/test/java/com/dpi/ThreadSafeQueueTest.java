package com.dpi;

import com.dpi.engine.ThreadSafeQueue;
import org.junit.Test;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class ThreadSafeQueueTest {

    @Test
    public void testBasicPushPop() {
        ThreadSafeQueue<Integer> queue = new ThreadSafeQueue<>(5);
        assertTrue(queue.push(1));
        assertTrue(queue.push(2));
        assertEquals(2, queue.size());

        Optional<Integer> first = queue.popWithTimeout(100);
        assertTrue(first.isPresent());
        assertEquals(Integer.valueOf(1), first.get());

        Optional<Integer> second = queue.popWithTimeout(100);
        assertTrue(second.isPresent());
        assertEquals(Integer.valueOf(2), second.get());

        assertFalse(queue.popWithTimeout(50).isPresent());
    }

    @Test
    public void testCapacityLimitAndBlocking() throws InterruptedException {
        ThreadSafeQueue<Integer> queue = new ThreadSafeQueue<>(2);
        assertTrue(queue.push(1));
        assertTrue(queue.push(2));

        // Push should block if queue is full. Let's test non-blocking push or check if it blocks.
        // ThreadSafeQueue.push blocks when full. Let's start a thread to pop it after 100ms.
        Thread popThread = new Thread(() -> {
            try {
                Thread.sleep(100);
                queue.popWithTimeout(100);
            } catch (InterruptedException e) {
                // ignore
            }
        });
        
        long startTime = System.currentTimeMillis();
        popThread.start();

        // This push should block until popThread pops an item
        assertTrue(queue.push(3));
        long duration = System.currentTimeMillis() - startTime;
        assertTrue(duration >= 90); // Should have waited at least 100ms
        
        popThread.join();
    }

    @Test
    public void testShutdown() throws InterruptedException {
        ThreadSafeQueue<Integer> queue = new ThreadSafeQueue<>(5);
        queue.push(1);
        queue.push(2);

        queue.shutdown();

        // Push should fail after shutdown
        assertFalse(queue.push(3));

        // Pop should still return remaining elements
        Optional<Integer> item = queue.popWithTimeout(50);
        assertTrue(item.isPresent());
        assertEquals(Integer.valueOf(1), item.get());

        Optional<Integer> item2 = queue.popWithTimeout(50);
        assertTrue(item2.isPresent());
        assertEquals(Integer.valueOf(2), item2.get());

        // Once empty, pop should return empty and not block
        Optional<Integer> empty = queue.popWithTimeout(50);
        assertFalse(empty.isPresent());
    }
}
