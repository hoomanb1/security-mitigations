/**
 * Copyright 2017 Hooman Broujerdi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.hoomanb1;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.zip.ZipInputStream;

import static java.lang.Math.toIntExact;

/**
 * <p>A GlobalFileUploadFilter configures a filter to have a fine-grained
 * control over file type upload.</p>
 *
 * <p>If this is configured via a system property with file.upload.filter
 * property key, an instance of this class will contain filters list as
 * MagicNumberFileFilter object. Callers can access these filters via
 * getFilterConfig() method. The filter list can then be passed into
 * <code>accept(byte[] fileContent, List&lt;MagicNumberFileFilter&gt; filters)</code>
 * along with file content bytes that need to be checked against these
 * filters. When <code>accept()</code> method is called, file magic number (Signature),
 * byte offset, file size, and any exception with regards to that file
 * content will be evaluated against the already configured filter.</p>
 *
 * <p>In addition to global filter configuration, filter can also be configured
 * on a use-case basis. If the application's file upload requirement is not the
 * same throughout the application, then this filter can also be configured
 * programmatically by calling <code>constructFilters(String config, List&lt;MagicNumberFileFilter&gt; filters)</code>
 * and providing the String pattern syntax for the filter configuration as well as an empty list
 * of the MagicNumberFileFilter type. The String config will be parsed and a list of filters
 * will be returned to the caller and eventually that list can be passed into <code>accept()</code></p>
 *
 * <p>For example to configure the filter to only allow a Zip file upload which contains ascii documents
 * with specific characters the filter configuration looks like below:</p>
 * <br>
 *     <pre>
 *         byte[] fileContentToCheck = ...;
 *         List&lt;MagicNumberFileFilter&gt; filters = GlobalFileUploadFilter.constructFilters(
 *                "signature=504B0304,offset=0,maxSize=25mb,exc=[@ ? %]", new ArrayList&lt;MagicNumberFileFilter&gt;());
 *         boolean isFileAllowed = GlobalFileUploadFilter.accept(fileContentToCheck, filters);
 *     </pre>
 *
 *
 *
 * <p>Filter pattern syntax definition:</p>
 * <br>
 * Signature: File magic number
 * <br>
 * offset: From which magic number starts
 * <br>
 * maxSize: max file size allowed
 * <br>
 * exc: List of space-separated characters allowed for Ascii files
 *<br>
 * Multiple filter patterns are separated via a dash "-".
 *
 *
 * @author Hooman Broujerdi
 * @version 1.0
 */

public class GlobalFileUploadFilter {

    private static final transient Logger LOG = LoggerFactory.getLogger(GlobalFileUploadFilter.class);
    private static final String FILE_UPLOAD_PROPNAME = "file.upload.filter";
    private static final String ZIP_SIGNATURE = "504B0304";
    private List<MagicNumberFileFilter> filters;

    public List<MagicNumberFileFilter> getFilterConfig() {
        return Collections.unmodifiableList(getFilters());
    }

    public GlobalFileUploadFilter() {

        String config = System.getProperty(FILE_UPLOAD_PROPNAME);
        if (config != null) {
            LOG.info("Configuring file upload using {} configurations", config);

            try {
                constructFilters(config, this.getFilters());
            } catch (RuntimeException e) {
                LOG.warn("Error configuring filter {}", config);
            }
        }
    }

    private static List<String> constructDefaultScriptingContent() {
        // Scripting content search with offset 0
        String[] scriptContentSearch = new String[]{"#!/usr/bin/python", "#!/usr/local/bin/python", "#!/bin/sh",
                "#!/usr/bin/env python", "#!/bin/bash", "#!/usr/bin/bash", "#!/usr/local/bash", "#!/usr/local/bin/bash",
                "#!/usr/bin/env bash", "=<?php", "=<?\\n", "=<?\\r", "#!/usr/local/bin/php", "#!/usr/bin/php",
                "#!/usr/bin/pdmenu", "eval \"exec perl", "eval \"exec /bin/perl", "eval \"exec /usr/bin/perl",
                "eval \"exec /usr/local/bin/perl", "eval 'exec perl", "eval 'exec /bin/perl", "eval 'exec /usr/bin/perl",
                "eval 'exec /usr/local/bin/perl", "eval '(exit $?0)' && eval 'exec", "#!/usr/bin/env perl",
                "#! /usr/bin/env perl", "#!/bin/node", "#!/usr/bin/node", "#!/bin/nodejs", "#!/usr/bin/nodejs",
                "#!/usr/bin/env node", "#!/usr/bin/env nodejs", "@", "echo off", "rem", "set", "<html>", "#!/usr/bin/env ruby",
                "#!/usr/bin/ruby", "#!", "<script>", "goscript", "//usr", "<%", "%>", "..", "/", "\\", "*", "?", "%", ";", "#",
                "$", "&", "[", "]", "^", "`", "~", ">>", "<<", "...", "#include", "stdio.h", "perl"};

        List<String> scriptingList = new ArrayList<String>();
        for (int i = 0; i <= scriptContentSearch.length - 1; i ++) {
            scriptingList.add(scriptContentSearch[i]);
        }

        return scriptingList;
    }

    /**
     *
     * @param config configuration pattern syntax
     * @param filters an empty list of filters to be populated
     * @return a list of filters based on config param
     */
    public static List<MagicNumberFileFilter> constructFilters(String config, List<MagicNumberFileFilter> filters) {
        if (!filters.isEmpty()) {
            throw new IllegalStateException("Filter list should not contain pre-configured list");
        }

        String[] var0 = config.split("-");
        for (int i = 0; i <= var0.length - 1; i++) {
            MagicNumberFileFilter filter = new MagicNumberFileFilter();
            String[] var1 = var0[i].split(",");
            for (int j = 0; j <= var1.length - 1; j++) {
                if (var1[j].toLowerCase().startsWith("signature=")) {
                    String value = var1[j].substring(10);
                    if (validateString(value)) {
                        filter.setMagicNumbers(hexStringToByteArray(value));
                    }
                }

                if (var1[j].toLowerCase().startsWith("offset=")) {
                    String value = var1[j].toLowerCase().substring(7);
                    if (validateString(value)) {
                        filter.setByteOffset(Long.parseLong(value));
                    }
                }

                if (var1[j].toLowerCase().startsWith("maxsize=")) {
                    String value = var1[j].substring(8);
                    if (validateString(value)) {
                        filter.setMaxSize(value.trim());
                    }

                }

                if (var1[j].toLowerCase().startsWith("exc=")) {
                    List<String> excns = new ArrayList<String>();
                    String tmpValue = var1[j].substring(5);
                    if (validateString(tmpValue) && tmpValue.charAt(tmpValue.length() - 1) == ']') {
                        tmpValue = tmpValue.substring(0, tmpValue.length() - 1);
                    }

                    String[] vars = tmpValue.split("\\s+");
                    for (int k = 0; k < vars.length; k ++) {
                        excns.add(vars[k]);
                    }

                    filter.setExceptions(!excns.isEmpty() ? excns : new ArrayList<String>());
                }
            }

            filters.add(filter);
        }

        return filters;
    }

    private static boolean validateString(String tmpValue) {
        return tmpValue != null && tmpValue.length() > 0;
    }

    protected static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    static long translateFileSize(String size) {

        if (size.toLowerCase().trim().contains("bytes")) {
            String normalized = size.toLowerCase().replace("bytes", "").trim();
            return Long.parseLong(!normalized.equals("") ? normalized : "0");
        }

        if (size.toLowerCase().trim().contains("kb")) {
            String normalized = size.toLowerCase().replace("kb", "").trim();
            return 1024L * Long.parseLong(!normalized.equals("") ? normalized : "0");
        }

        if (size.toLowerCase().trim().contains("mb")) {
            String normalized = size.toLowerCase().replace("mb", "").trim();
            return 1048576L * Long.parseLong(!normalized.equals("") ? normalized : "0");
        }

        if (size.toLowerCase().trim().contains("gb")) {
            String normalized = size.toLowerCase().replace("gb", "").trim();
            return 1073741824L * Long.parseLong(!normalized.equals("") ? normalized : "0");
        }

        return 0L;
    }

    /**
     * Reads file content as byte array and checks the
     * magic number associated with the file type
     *
     * @param fileContent file content to be checked
     * @param filters     List of filters to be checked against file content
     * @return whether file content matches filter's condition
     */
    public static synchronized boolean accept(byte[] fileContent, List<MagicNumberFileFilter> filters) {
        // By default all files are allowed unless configured via sys. prop
        if (filters == null || filters.isEmpty()) {
            return true;
        }

        boolean fileAccepted = false;

        for (MagicNumberFileFilter magicNumberFileFilter : filters) {
            if (magicNumberFileFilter.getMagicNumbers().length > 0 && fileContent.length >= magicNumberFileFilter.getByteOffset() +
                    magicNumberFileFilter.getMagicNumbers().length) {
                byte[] fileMagicBytes = Arrays.copyOfRange(fileContent, toIntExact(magicNumberFileFilter.getByteOffset()),
                        toIntExact(magicNumberFileFilter.getByteOffset()) + magicNumberFileFilter.getMagicNumbers().length);
                boolean matched = Arrays.equals(magicNumberFileFilter.getMagicNumbers(), fileMagicBytes);
                if (matched) {
                    fileAccepted = true;
                    //Individual file size check to ensure it complies with configs
                    if (magicNumberFileFilter.getMaxSize() != null) {
                        String fileSize = FileUtils.byteCountToDisplaySize(fileContent.length);
                        if (translateFileSize(fileSize) <= translateFileSize(magicNumberFileFilter.getMaxSize())) {
                            fileAccepted = true;
                        } else {
                            fileAccepted = false;
                        }
                    }

                    //If this is a zip file inspect the content, at the moment hawtio should only
                    //allow zip archive file to be uploaded
                    if (Arrays.equals(magicNumberFileFilter.getMagicNumbers(),
                            hexStringToByteArray(ZIP_SIGNATURE)) && fileAccepted) {
                        try {
                            fileAccepted = unzip(fileContent, filters);
                        } catch (IOException e) {
                            throw new RuntimeException("Internal Error occurred during file content inspection");
                        }
                    }
                }
            } else if (magicNumberFileFilter.getExceptions() != null) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream(fileContent.length);
                outputStream.write(fileContent, 0, fileContent.length);
                Set<String> excList = new HashSet<>();
                for (String s : constructDefaultScriptingContent()) {
                    if (magicNumberFileFilter.getExceptions() != null &&
                            !magicNumberFileFilter.getExceptions().contains(s)) {
                        excList.add(s);
                    }
                }
                if (!isAsciiContentDangerous(outputStream, excList)) {
                    fileAccepted = true;
                }
            }
        }

        return fileAccepted;
    }

    private static boolean unzip(byte[] fileContent, List<MagicNumberFileFilter> fileFilter) throws IOException {
        long maxSize = 5 * 1048576L; // Default size of the unzipped data, 50MB
        int tooMany = 100; // Max number of files
        int buffer = 512;
        ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(fileContent));
        boolean safe = true;
        int entries = 0;
        long total = 0;
        try {
            while ((zipInputStream.getNextEntry()) != null) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                int count;
                byte[] data = new byte[buffer];
                boolean isAscii = true;
                while (total + buffer <= maxSize && (count = zipInputStream.read(data, 0, buffer)) != -1) {
                    if (isAscii) {
                        isAscii = isAsciiFile(data, count); // Check if the stream is ascii.
                    }

                    outputStream.write(data, 0, count);
                    total += count;
                }

                if (outputStream.toByteArray().length > 0) {
                    // Check the entry file type
                    byte[] entryContent = outputStream.toByteArray();
                    boolean configured = accept(entryContent, fileFilter);
                    if (configured) {
                        continue; // valid file
                    }

                    if (isAscii) {
                        if (!configured && isExceptionConfigured(fileFilter)) {
                            Set<String> finalProhibitedList = getFinalProhibitedList(fileFilter);

                            if (!isAsciiContentDangerous(outputStream, finalProhibitedList)) {
                                safe = true;
                            } else {
                                safe = false;
                            }
                        }

                        if (!configured && !isExceptionConfigured(fileFilter)) {
                            if (!isAsciiContentDangerous(outputStream,
                                    new HashSet<>(constructDefaultScriptingContent()))) {
                                safe = true;
                            } else {
                                safe = false;
                            }
                        }
                    } else safe = false;
                }

                if (!safe) {
                    return safe;
                }

                if (outputStream != null) {
                    outputStream.close();
                }
            }

            zipInputStream.closeEntry();
            entries ++;
            if (entries > tooMany) {
                throw new IllegalStateException("Too many files to unzip");
            }

            if (total > maxSize) {
                throw new IllegalStateException("File being unzipped is too big");
            }
        } finally {
            zipInputStream.close();
        }

        return safe;
    }

    static boolean isAsciiFile(byte[] content, int len) {
        for (int i = 0; i < len; i ++) {
            if ((0x0080 & content[i]) != 0) {
                return false;
            }
        }

        return true;
    }

    static Set<String> getFinalProhibitedList(List<MagicNumberFileFilter> fileFilter) {
        Set<String> finalProhibitedList = new HashSet<>();

        // Checking for exceptions: Nested loop should not be inefficient
        // as the filter usually does not grow unexpectedly
        for (String s: constructDefaultScriptingContent()) {
            for (MagicNumberFileFilter m: fileFilter) {
                if (m.getExceptions() != null && !m.getExceptions().contains(s)) {
                    finalProhibitedList.add(s);
                }
            }
        }
        return finalProhibitedList;
    }

    private static boolean isExceptionConfigured(List<MagicNumberFileFilter> fileFilter) {
        boolean configured = true;
        for (MagicNumberFileFilter filter: fileFilter) {
            if (filter.getExceptions() == null) {
                configured = false;
            } else {
                configured = true;
            }
        }
        return configured;
    }

    static boolean isAsciiContentDangerous(ByteArrayOutputStream outputStream,
                                           Set<String> finalProhibitedList) {
        boolean dangerousContentDetected = false;

        StringBuilder builder = new StringBuilder();
        for (byte b: outputStream.toByteArray()) {
            builder.append((char)b);
        }

        for (String s: finalProhibitedList) {
            if (builder.toString().startsWith(s) || builder.toString().contains(s)) {
                dangerousContentDetected = true; // script file detected
            }
        }

        return dangerousContentDetected;
    }

    /**
     *
     * @param filters list of filters
     * @return max file size based on configs
     */
    public static long getMaxFileSizeAllowed(List<MagicNumberFileFilter> filters) {
        if (filters.size() == 0) {
            return -1L; // Default file size unlimited
        }

        long maxSize = -1L;
        try {
            long[] fileSizes = new long[filters.size()];
            for (int i = 0; i <= filters.size() - 1; i ++) {
                fileSizes[i] = translateFileSize(filters.get(i).getMaxSize());
            }

            maxSize = fileSizes[0];
            for (int j = 0; j <= fileSizes.length - 1; j ++) {
                if (maxSize == fileSizes[j]) {
                    continue;
                }

                if (fileSizes[j] > maxSize) {
                    maxSize = fileSizes[j];
                }
            }
        } catch (RuntimeException e) {
            LOG.error("Error calculating max file size");
        }

        return maxSize;
    }

    /**
     *
     * @return an instance of GlobalFileUploadFilter with configured system property configured filters
     */
    public static GlobalFileUploadFilter newFileUploadFilter() {
        return new GlobalFileUploadFilter();
    }

    private List<MagicNumberFileFilter> getFilters() {
        if (this.filters == null) {
            this.filters = new ArrayList<>();
        }

        return this.filters;
    }

    /**
     * Hold a snapshot of values to be passed to an GlobalFileUploadFilter.
     */
    public static final class MagicNumberFileFilter {
        private byte[] magicNumbers;
        private long byteOffset;
        private String maxSize;
        private List<String> exceptions;

        public MagicNumberFileFilter() {
            this.magicNumbers = new byte[0];
            this.maxSize = "200bytes";
        }

        public byte[] getMagicNumbers() {
            return magicNumbers;
        }

        public void setMagicNumbers(byte[] magicNumbers) {
            if (magicNumbers.length == 0) {
                throw new IllegalArgumentException("The magic number must contain at least one byte");
            }
            this.magicNumbers = magicNumbers;
        }

        public long getByteOffset() {
            return byteOffset;
        }

        public void setByteOffset(long byteOffset) {
            if (byteOffset < 0L) {
                throw new IllegalArgumentException("The offset cannot be negative");
            }
            this.byteOffset = byteOffset;
        }

        /**
         * Method getMaxSize returns the maxSize of MagicNumberFileFilter class object
         * @return max file size
         */
        public String getMaxSize() {
            return maxSize;
        }

        /**
         * Method setMaxSize sets the maxSize of MagicNumberFileFilter class object
         * @param maxSize the max file size
         */
        public void setMaxSize(String maxSize) {
            if (maxSize != null) {
                this.maxSize = maxSize;
            }
        }

        public List<String> getExceptions() {
            return exceptions;
        }

        public void setExceptions(List<String> exceptions) {
            this.exceptions = exceptions;
        }
    }
}

