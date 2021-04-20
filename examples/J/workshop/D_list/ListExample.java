/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.D_list;

import com.intel.pmem.llpl.PersistentHeap;
import com.intel.pmem.llpl.AnyHeap;
import workshop.util.Util;

public class ListExample {
	public static void main(String[] args) throws java.io.IOException {
		long heapSize = 20_000_000L;
		String heapName = Util.pmemHome() + "D_list";
		boolean firstRun = !AnyHeap.exists(heapName);
        AnyHeap heap = firstRun
                     ? PersistentHeap.createHeap(heapName, heapSize)
                     : PersistentHeap.openHeap(heapName);

		if (firstRun) {
            System.out.println("D) Creating new List with 5 elements");
            heap.execute(()-> {
               	List list = new List(heap);
                heap.setRoot(list.handle());
                list.insert(200);
                list.insert(300);
                list.insert(100);
                list.insert(500);
                list.insert(400);
            });
		}
		else {
			long listHandle = heap.getRoot();
			List list = new List(heap, listHandle);
            System.out.print("D) Retrieved list\n ");
            long node = list.head();
            while (node != 0) {
            	long value = list.getValue(node);
                System.out.print(" Node(" + value + ") -> ");
                node = list.getNext(node);
            }
            System.out.println("End");
            System.out.format("  list max value = %d\n", list.maxValue()); 
		}
	}
}