/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.A_intarray;

import com.intel.pmem.llpl.TransactionalHeap;
import com.intel.pmem.llpl.TransactionalMemoryBlock;

public class IntArray {
    private static final long SIZE_OFFSET = 0;
    private static final long HEADER_SIZE = 8;
    private final TransactionalMemoryBlock arrayBlock;

    public IntArray(TransactionalHeap heap, long size) {
        this.arrayBlock = heap.allocateMemoryBlock(HEADER_SIZE + size * Integer.BYTES);
        arrayBlock.setLong(SIZE_OFFSET, size);
    }

    public static IntArray fromHandle(TransactionalHeap heap, long handle) {
        TransactionalMemoryBlock arrayBlock = heap.memoryBlockFromHandle(handle);
        return new IntArray(arrayBlock);
    }

    private IntArray(TransactionalMemoryBlock arrayBlock) {
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
        arrayBlock.free();
    }
}