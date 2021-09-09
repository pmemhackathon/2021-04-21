import io.pmem.pmemkv.Converter;
import io.pmem.pmemkv.Database;
import io.pmem.pmemkv.NotFoundException;

import java.nio.ByteBuffer;

/*
 * Implementation of Converter interface to allow
 * storing in the Database keys and values as Strings.
 */
class StringConverter implements Converter<String> {
	public ByteBuffer toByteBuffer(String entry) {
		return ByteBuffer.wrap(entry.getBytes());
	}

	public String fromByteBuffer(ByteBuffer entry) {
		byte[] bytes;
		bytes = new byte[entry.capacity()];
		entry.get(bytes);
		return new String(bytes);
	}
}

public class PmemkvExample {
	/*
	 * this is the main program, used this way:
	 *	java PmemkvExample pmemfile      -- print all the keys and values in the pmemfile
	 *	java PmemkvExample pmemfile key  -- lookup key and print the value
	 *	java PmemkvExample pmemfile key value -- add a key/value pair to the pmemfile
	 *
	 * the pmemfile is created automatically if it doesn't already exist.
	 */

	public static void main(String[] args) {
		int SIZE = 10 * 1024 * 1024; // 10 MiB
		String ENGINE = "cmap";

		if (args.length < 1 || args.length > 3) {
			System.err.println("Usage: java PmemkvExample kvfile [key [value]]");
			System.exit(1);
		}

		/*
		 * Configure and open Database, using Builder.
		 * Part of the configuration is given (as an example) as JSON Object.
		 * Note, it is required to define key and value converter (to/from ByteBuffer).
		 */
		Database<String, String> db = new Database.Builder<String, String>(ENGINE)
				.fromJson("{\"path\":\"" + args[0] + "\", \"create_if_missing\":1}")
				.setSize(SIZE)
				.setKeyConverter(new StringConverter())
				.setValueConverter(new StringConverter())
				.build();

		if (args.length == 1) {

			// iterate through the key-value store, printing them
			db.getAll((String k, String v) -> {
				System.out.println(k + "=\"" + v + "\"");
			});
		} else if (args.length == 2) {

			// lookup the given key and print the value
			try {
				db.get(args[1], (String v) -> {
					System.out.println(args[1] + "=\"" + v + "\"");
				});
			} catch (NotFoundException e) {
				System.out.println("Key '" + args[1] + "' wasn't found in DB");
			}
		} else {

			// add the given key-value pair
			db.put(args[1], args[2]);
		}

		db.stop();
	}
}
