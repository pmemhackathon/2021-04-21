/* 
 * Copyright (C) 2021 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 */

package workshop.E_recordlog;

import com.intel.pmem.llpl.MemoryPool;

public class RecordLog {
    private static final long END_OFFSET_OFFSET = 0;    // long
    private static final long RECORD_COUNT_OFFSET = 8;  // long
    private static final long DATA_START_OFFSET = 16;
    private final MemoryPool pool;
    

    public static RecordLog create(MemoryPool pool) {
        RecordLog log = new RecordLog(pool);
        log.updateHeader(DATA_START_OFFSET, 0);
        return log;
    }

    public static RecordLog open(MemoryPool pool) {
        return new RecordLog(pool);
    }

    private RecordLog(MemoryPool pool) {
        this.pool = pool;
    }

    private MemoryPool pool() {
        return pool;
    }

    public  long getStartOffset() {
        return DATA_START_OFFSET;
    }

    public long getEndOffset() {
        return pool.getLong(END_OFFSET_OFFSET);
    }

    public long getNextRecordOffset(long recordOffset) {
        return recordOffset + Record.HEADER_SIZE + Record.getPayloadLength(this, recordOffset);
    }

    private void updateHeader(long endOffset, long recordCount) {
        pool.setLong(END_OFFSET_OFFSET, endOffset);
        pool.setLong(RECORD_COUNT_OFFSET, recordCount);
        pool.flush(END_OFFSET_OFFSET, Long.BYTES + Long.BYTES);
    }

    public long getRecordCount() {
        return pool.getLong(RECORD_COUNT_OFFSET);
    }

    public static class Record {
        private static final long ID_OFFSET = 0;
        private static final long PAYLOAD_LENGTH_OFFSET = 8;
        private static final long HEADER_SIZE = 16; 

        public static void appendTo(RecordLog log, byte[] payload) {
        	long recordOffset = log.getEndOffset();
            long recordId = log.getRecordCount() + 1;
            int payloadLength = payload.length;
            MemoryPool pool = log.pool();
            pool.setLong(recordOffset + ID_OFFSET, recordId);
            pool.setInt(recordOffset + PAYLOAD_LENGTH_OFFSET, payloadLength);
            pool.copyFromByteArray(payload, 0, recordOffset + HEADER_SIZE, payloadLength);
            pool.flush(recordOffset, HEADER_SIZE + payloadLength);
            log.updateHeader(recordOffset + HEADER_SIZE + payloadLength, recordId);
        }

        public static long getId(RecordLog log, long recordOffset) {
            return log.pool().getLong(recordOffset + ID_OFFSET);
        }

        public static int getPayloadLength(RecordLog log, long recordOffset) {
            return log.pool().getInt(recordOffset + PAYLOAD_LENGTH_OFFSET);
        }

        public static int getPayload(RecordLog log, long recordOffset, byte[] buffer) {
        	MemoryPool pool = log.pool();
        	int payloadLength = getPayloadLength(log, recordOffset);
            pool.copyToByteArray(recordOffset + HEADER_SIZE, buffer, 0, payloadLength);
            return payloadLength;
        }
    }
}