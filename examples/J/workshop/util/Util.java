package workshop.util;

public class Util {
	public static String pmemHome() {
		return System.getProperty("PMEM_HOME", "/mnt/mem/");
	}
}
