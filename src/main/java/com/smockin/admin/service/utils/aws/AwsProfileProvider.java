package com.smockin.admin.service.utils.aws;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

@Component
public class AwsProfileProvider {

    private static final String DEFAULT = "default";

    private static final String AWS_CREDENTIALS_FILE = System.getProperty("user.home") + "/.aws/credentials";

    public AwsProfile findDefaultProfile() throws IOException {
        return findAllProfiles().get(DEFAULT);
    }

    public Map<String, AwsProfile> findAllProfiles() throws IOException {
        return findAllProfiles(AWS_CREDENTIALS_FILE);
    }

    public Map<String, AwsProfile> findAllProfiles(String file) throws IOException {
        Map<String, Map<String, String>> profiles = IniParser.parse(file);
        return profiles.entrySet().stream().map(this::createAwsProfile)
                .collect(Collectors.toMap(AwsProfile::getProfile, Function.identity()));
    }

    private AwsProfile createAwsProfile(Map.Entry<String, Map<String, String>> entry) {
        return new AwsProfile(
                entry.getKey(),
                entry.getValue().get("aws_access_key_id"),
                entry.getValue().get("aws_secret_access_key"),
                entry.getValue().get("region")
        );
    }

}

class IniParser {
    private final Map<String, Map<String, String>> values = new HashMap<>();
    private String currentSection = "default";

    private IniParser(String fileName) throws IOException {
        final File file = new File(fileName);
        if (file.isFile()) {
            try (BufferedReader lineReader = Files.newBufferedReader(Paths.get(file.toURI()))) {
                lineReader.lines()
                        .map(String::trim)
                        .filter(line -> !line.startsWith(";"))
                        .forEachOrdered(this::processLine);
            }
        }
    }

    private void processLine(String line) {
        if (line.startsWith("[") && line.endsWith("]")) {
            currentSection = line.substring(1, line.length() - 1).trim();
        } else {
            String[] pair = line.split("=");
            if (pair.length == 2) {
                Map<String, String> section = values.computeIfAbsent(currentSection, key -> new HashMap<>());
                section.put(pair[0].trim(), pair[1].trim());
            }
        }
    }

    public static Map<String, Map<String, String>> parse(String file) throws IOException {
        return new IniParser(file).values;
    }
}
