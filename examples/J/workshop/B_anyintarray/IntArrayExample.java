/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.B_anyintarray;

import com.intel.pmem.llpl.Heap;
import com.intel.pmem.llpl.PersistentHeap;
import com.intel.pmem.llpl.TransactionalHeap;
import com.intel.pmem.llpl.AnyHeap;
import com.intel.pmem.llpl.AnyMemoryBlock;
import workshop.util.Util;

public class IntArrayExample{
    public static void main(String[] args) {
        String heapName = Util.pmemHome() + "B_anyintarray";
        long heapSize = 20_000_000L;
        boolean firstRun = !AnyHeap.exists(heapName);
        AnyHeap heap = firstRun
                     ? PersistentHeap.createHeap(heapName, heapSize)
                     : PersistentHeap.openHeap(heapName);
                     
        if (firstRun) {
            long size = 10;
            System.out.println("B) Creating New Array of size " + size);
            heap.execute(()-> {
                IntArray array = new IntArray(heap, size);
                heap.setRoot(array.handle());
                array.set(5, 30);
                array.set(7, 40);
            });
        }
        else {
            IntArray array = IntArray.fromHandle(heap, heap.getRoot());
            System.out.println("B) Retrieved IntArray of size " + array.size());
            for (long i = 0; i < array.size(); i++) {
                int val = array.get(i);
                System.out.println("  IntArray[" + i + "] = " + val);
            }
        }
    }
}
