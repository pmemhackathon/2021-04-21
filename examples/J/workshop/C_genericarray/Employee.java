/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.C_genericarray;

import com.intel.pmem.llpl.AnyHeap;
import com.intel.pmem.llpl.AnyMemoryBlock;
import com.intel.pmem.llpl.Range;
import java.util.function.Function;

public class Employee implements Array.Element {
    private static final int MAX_NAME_SIZE = 20;
    private static final long ID_OFFSET = 0;            // long
    private static final long NAME_LENGTH_OFFSET = 8;   // int
    private static final long NAME_OFFSET = 12;
    public static final long BYTE_SIZE = 12 + MAX_NAME_SIZE;
    private final AnyMemoryBlock block;
    
    public Employee(AnyHeap heap, String name, long id) {
        block = heap.allocateMemoryBlock(BYTE_SIZE, (Range range) -> { 
            range.setLong(ID_OFFSET, id);
            byte[] nameBytes = name.getBytes();
            range.setInt(NAME_LENGTH_OFFSET, nameBytes.length);
            range.copyFromArray(nameBytes, 0, NAME_OFFSET, Math.min(nameBytes.length, MAX_NAME_SIZE));
        });
    }
   
    public Employee(AnyMemoryBlock block) {
        this.block = block;
    }
    
    public long getId() {
        return block.getLong(ID_OFFSET);
    }

    public String getName() {
        int nameLength = block.getInt(NAME_LENGTH_OFFSET);
        byte[] bytes = new byte[nameLength];
        block.copyToArray(NAME_OFFSET, bytes, 0, nameLength);
        return new String(bytes);
    }
     
    @Override
    public String toString() {
        return String.format("Employee(%s, %d)", getName(), getId());
    }
   
    // implement Array.Element
    @Override
    public void free() {
        block.freeMemory();    
    }

    @Override 
    public long handle() {
        return block.handle();
    }

    public static Function<Long, Employee> recreator(AnyHeap heap) {
        return (handle) -> new Employee(heap.memoryBlockFromHandle(handle));
    }
}
