/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.D_list;

import com.intel.pmem.llpl.AnyHeap;
import com.intel.pmem.llpl.AnyMemoryBlock;
import com.intel.pmem.llpl.AnyAccessor;

public class List {
    private final AnyHeap heap;
    private final AnyMemoryBlock headSlot;
    private final AnyAccessor accessor;

    public List(AnyHeap heap) {
        this.heap = heap;
        accessor = heap.createAccessor();
        headSlot = heap.allocateMemoryBlock(Long.BYTES);
    }
    
    public List(AnyHeap heap, long handle) {
        this.heap = heap;
        accessor = heap.createAccessor();
        headSlot = heap.memoryBlockFromHandle(handle);
    }

    public long head() {
        return headSlot.getLong(0);
    }

    private void head(long handle) {
        headSlot.setLong(0, handle);
    }
    
    public void insert(long value) {
        heap.execute(() -> {
            long newNode = Node.create(heap, accessor, value, head());
            head(newNode);
        });
    }

    public long getValue(long node) {
        accessor.handle(node);
        return Node.getValue(accessor);
    }

    public long getNext(long node) {
        accessor.handle(node);
        return Node.getNext(accessor);
    }

    public long handle() {
        return headSlot.handle();
    }

    public long maxValue() {
        long node = head();
        long max = 0;
        while (node != 0) {
            accessor.handle(node);
            max = Math.max(max, Node.getValue(accessor));
            node = Node.getNext(accessor);
        }
        return max;
    }

    private static class Node {
        private static final long NODE_VALUE_OFFSET = 0;   // long
        private static final long NODE_NEXT_OFFSET = 8;    // long
        private static final long NODE_SIZE = 16;

        public static long create(AnyHeap heap, AnyAccessor accessor, long value, long nextNode) {
            long newNode = heap.allocateMemory(NODE_SIZE);
            accessor.handle(newNode);
            accessor.setLong(NODE_VALUE_OFFSET, value);
            accessor.setLong(NODE_NEXT_OFFSET, nextNode);
            return newNode;
        }

        public static long getValue(AnyAccessor accessor) {
            return accessor.getLong(NODE_VALUE_OFFSET);
        }

        public static long getNext(AnyAccessor accessor) {
            return accessor.getLong(NODE_NEXT_OFFSET);
        }
    }
}
