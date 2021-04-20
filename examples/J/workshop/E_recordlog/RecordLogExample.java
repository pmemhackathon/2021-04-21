package workshop.E_recordlog;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import com.intel.pmem.llpl.MemoryPool;
import static workshop.E_recordlog.RecordLog.Record;
import workshop.util.Util;

public class RecordLogExample {
    public static void main(String[] args) {
        long poolSize = 20_000_000L;
        String poolName = Util.pmemHome() + "E_recordlog";
        boolean firstRun = !Files.exists(Paths.get(poolName));
        RecordLog log;
        if (firstRun) {
            MemoryPool pool = MemoryPool.createPool(poolName, poolSize);
            log = RecordLog.create(pool);
            Record.appendTo(log, "Saturn".getBytes());
            Record.appendTo(log, "Pluto".getBytes());
            Record.appendTo(log, "Mercury".getBytes());
            System.out.format("E) Wrote %d records to log\n", log.getRecordCount());
        }
        else {
            MemoryPool pool = MemoryPool.openPool(poolName);  
            log = RecordLog.open(pool);
            long recordOffset = log.getStartOffset();
            long endOffset = log.getEndOffset();
            byte[] buffer = new byte[4096];
            System.out.format("E) Reading records\n", log.getRecordCount());
            while (recordOffset < endOffset) {
                long id = Record.getId(log, recordOffset);
                int payloadLength = Record.getPayload(log, recordOffset, buffer);
                System.out.format("   Record(%d, %s)\n", id, new String(buffer, 0, payloadLength));
                recordOffset = log.getNextRecordOffset(recordOffset);
            }
        }
    }
}