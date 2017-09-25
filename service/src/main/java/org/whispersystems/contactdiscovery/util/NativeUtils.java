/*
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.whispersystems.contactdiscovery.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class NativeUtils {

  public static File extractNativeResource(String resource) throws IOException {
    File tempFile = Files.createTempFile("resource", "so").toFile();
    tempFile.deleteOnExit();

    OutputStream out = new FileOutputStream(tempFile);
    InputStream  in  = NativeUtils.class.getResourceAsStream(resource);

    if (in == null) throw new IOException("No such resource: " + resource);

    FileUtils.copy(in, out);

    return tempFile;
  }

  public static void loadNativeResource(String resource) throws IOException {
    File extracted = extractNativeResource(resource);
    System.load(extracted.getAbsolutePath());
  }


}
