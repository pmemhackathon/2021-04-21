/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.A_intarray;

import com.intel.pmem.llpl.Transaction;
import com.intel.pmem.llpl.TransactionalHeap;
import com.intel.pmem.llpl.TransactionalMemoryBlock;
import workshop.util.Util;

public class IntArrayExample{
    public static void main(String[] args) {
        String heapName = Util.pmemHome() + "A_intarray";
        long heapSize = 20_000_000L;
        boolean firstRun = !TransactionalHeap.exists(heapName);
        TransactionalHeap heap = firstRun
                               ? TransactionalHeap.createHeap(heapName, heapSize)
                               : TransactionalHeap.openHeap(heapName);
        if (firstRun) {
            long size = 10;
            System.out.println("A) Creating New Array of size " + size);
            Transaction.create(heap, ()-> {
                IntArray array = new IntArray(heap, size);
                heap.setRoot(array.handle());
                array.set(5, 10);
                array.set(7, 20);
            });
        }
        else {
            IntArray array = IntArray.fromHandle(heap, heap.getRoot());
            System.out.println("A) Retrieved IntArray of size " + array.size());
            for (long i = 0; i < array.size(); i++) {
                int val = array.get(i);
                System.out.println("  IntArray[" + i + "] = " + val);
            }
        }
    }
}
