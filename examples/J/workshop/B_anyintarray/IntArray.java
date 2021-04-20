/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.B_anyintarray;

import com.intel.pmem.llpl.AnyHeap;
import com.intel.pmem.llpl.AnyMemoryBlock;

public class IntArray {
    private static final long SIZE_OFFSET = 0;
    private static final long HEADER_SIZE = 8;
    private final AnyMemoryBlock arrayBlock;

    public IntArray(AnyHeap heap, long size) {
        this(heap.allocateMemoryBlock(HEADER_SIZE + Integer.BYTES * size));
        arrayBlock.setLong(SIZE_OFFSET, size);
    }

    public static IntArray fromHandle(AnyHeap heap, long handle) {
        AnyMemoryBlock arrayBlock = heap.memoryBlockFromHandle(handle);
        return new IntArray(arrayBlock);
    }

    private IntArray(AnyMemoryBlock arrayBlock) {
        this.arrayBlock = arrayBlock;
    }

    public void set(long index, int value) {
        arrayBlock.setInt(HEADER_SIZE + Integer.BYTES * index, value);
    }

    public int get(long index) {
        return arrayBlock.getInt(HEADER_SIZE + Integer.BYTES * index);
    }

    public long size() {
        return arrayBlock.getLong(SIZE_OFFSET);
    }

    public long handle() {
        return arrayBlock.handle();
    }

    public void free() {
        arrayBlock.freeMemory();
    }
}
