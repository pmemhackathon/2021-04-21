/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.C_genericarray;

import com.intel.pmem.llpl.AnyHeap;
import com.intel.pmem.llpl.AnyMemoryBlock;
import java.util.function.Function;

public class Array<T extends Array.Element> {
    private static final long SIZE_OFFSET = 0;
	private static final long HEADER_SIZE = 8;
	private final Function<Long, T> recreator;
	private final AnyMemoryBlock data;

	public interface Element {
		long handle();
		void free();
	}

	public Array(AnyHeap heap, long size, Function<Long, T> recreator) {
		this(recreator, heap.allocateMemoryBlock(HEADER_SIZE + size * Long.BYTES));
		data.setLong(SIZE_OFFSET, size);
	}

	public static <T extends Array.Element> Array<T> fromHandle(AnyHeap heap, long handle, Function<Long, T> recreator) {
		return new Array<T>(recreator, heap.memoryBlockFromHandle(handle));
	}

	private Array(Function<Long, T> recreator, AnyMemoryBlock data) {
		this.recreator = recreator;
		this.data = data;
	}
	
	public void set(long index, T value) {
		data.setLong(HEADER_SIZE + index * Long.BYTES, value.handle());
	}

	public T get(long index) {
		long handle = data.getLong(HEADER_SIZE + index * Long.BYTES);
		return handle == 0 ? null : recreator.apply(handle);
	}

	public long size() {
		return data.getLong(SIZE_OFFSET);
	}
	
	public long handle() {
		return data.handle();
	}

	public void free() {
		for (long i = 0; i < size(); i++) {
			T element = get(i);
			if (element != null) element.free();
		}
		data.freeMemory();
	}
}