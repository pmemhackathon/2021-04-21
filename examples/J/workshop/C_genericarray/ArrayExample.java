/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.C_genericarray;

import com.intel.pmem.llpl.Heap;
import com.intel.pmem.llpl.PersistentHeap;
import com.intel.pmem.llpl.TransactionalHeap;
import com.intel.pmem.llpl.AnyHeap;
import java.util.function.Function;
import workshop.util.Util;

public class ArrayExample {
	public static void main(String[] args) throws java.io.IOException {
		long heapSize = 20_000_000L;
		String heapName = Util.pmemHome() + "C_genericarray";
		boolean firstRun = !AnyHeap.exists(heapName);
        AnyHeap heap = firstRun
                     ? TransactionalHeap.createHeap(heapName, heapSize)
                     : TransactionalHeap.openHeap(heapName);

		if (firstRun) {
            long size = 10;
            System.out.println("C) Creating new Array of size " + size);
            heap.execute(()-> {
               	Array<Employee> array = new Array<>(heap, size, Employee.recreator(heap));
                heap.setRoot(array.handle());
                array.set(5, new Employee(heap, "Saturn", 10));
                array.set(7, new Employee(heap, "Pluto", 20));
            });
		}
		else {
			Array<Employee> array = Array.fromHandle(heap, heap.getRoot(), Employee.recreator(heap));
            System.out.println("C) Retrieved Array of size " + array.size());
            for (long i = 0; i < array.size(); i++) {
                Employee e = array.get(i);
                System.out.println("  Array[" + i + "] = " + e);
            }
            // clean up if done with array
            //array.free();
            //heap.setRoot(0);
		}
	}
}