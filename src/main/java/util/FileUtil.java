package util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class FileUtil {

	public static void saveFile(String name, byte[] data) throws IOException {
		OutputStream os = new FileOutputStream(name);
		os.write(data);
		os.flush();
		os.close();
	}
	
}
