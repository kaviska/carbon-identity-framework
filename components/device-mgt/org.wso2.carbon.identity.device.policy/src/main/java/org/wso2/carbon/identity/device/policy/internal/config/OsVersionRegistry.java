/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.device.policy.internal.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.rule.evaluation.api.resolver.SymbolicValueResolver;
import org.wso2.carbon.identity.rule.management.api.model.Value;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Singleton registry that loads os-versions.json and resolves symbolic OS version names.
 * Symbolic names: LATEST_ANDROID, SECOND_LATEST_ANDROID, LATEST_IOS, SECOND_LATEST_IOS,
 * LATEST_MACOS, SECOND_LATEST_MACOS, LATEST_WINDOWS, SECOND_LATEST_WINDOWS.
 * When admin updates os-versions.json and restarts, all policies using symbolic names auto-resolve.
 */
public class OsVersionRegistry implements SymbolicValueResolver {

    private static final Log LOG = LogFactory.getLog(OsVersionRegistry.class);
    private static final String CONFIG_PATH = "repository" + File.separator + "resources"
            + File.separator + "identity" + File.separator + "device-policy"
            + File.separator + "os-versions.json";

    private static volatile OsVersionRegistry instance;
    private Map<String, List<String>> platformVersions = Collections.emptyMap();

    private OsVersionRegistry() {

        load();
    }

    /**
     * Returns the singleton instance, initializing it on first call.
     */
    public static OsVersionRegistry getInstance() {

        if (instance == null) {
            synchronized (OsVersionRegistry.class) {
                if (instance == null) {
                    instance = new OsVersionRegistry();
                }
            }
        }
        return instance;
    }

    @Override
    public Value resolve(String symbolicValue) {

        if (symbolicValue.contains(",")) {
            return new Value(Value.Type.LIST, resolveList(symbolicValue));
        }
        return new Value(Value.Type.NUMBER, resolveToken(symbolicValue));
    }

    /**
     * Resolves a comma-separated value string, replacing any symbolic names with actual version numbers.
     * Non-symbolic tokens (plain numbers) are passed through unchanged.
     *
     * @param commaSeparated Comma-separated list, e.g. "LATEST_ANDROID,13,14".
     * @return Resolved comma-separated numbers, e.g. "15,13,14".
     */
    public String resolveList(String commaSeparated) {

        return Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .map(this::resolveToken)
                .collect(Collectors.joining(","));
    }

    /**
     * Resolves a single symbolic OS version token (e.g. LATEST_ANDROID) to its actual version number.
     * Returns the token unchanged if it is not a recognised symbolic name.
     *
     * @param token Symbolic token or plain version string.
     * @return Resolved version string.
     */
    public String resolveToken(String token) {

        switch (token) {
            case "LATEST_ANDROID":         return getLatest("android");
            case "SECOND_LATEST_ANDROID":  return getSecondLatest("android");
            case "LATEST_IOS":             return getLatest("ios");
            case "SECOND_LATEST_IOS":      return getSecondLatest("ios");
            case "LATEST_MACOS":           return getLatest("macos");
            case "SECOND_LATEST_MACOS":    return getSecondLatest("macos");
            case "LATEST_WINDOWS":         return getLatest("windows");
            case "SECOND_LATEST_WINDOWS":  return getSecondLatest("windows");
            default:                       return token;
        }
    }

    private String getLatest(String platform) {

        List<String> versions = platformVersions.get(platform);
        if (versions == null || versions.isEmpty()) {
            LOG.warn("No versions found for platform: " + platform + ". Returning 0.");
            return "0";
        }
        return versions.get(versions.size() - 1);
    }

    private String getSecondLatest(String platform) {

        List<String> versions = platformVersions.get(platform);
        if (versions == null || versions.size() < 2) {
            LOG.warn("Not enough versions for second_latest of platform: " + platform + ". Returning 0.");
            return "0";
        }
        return versions.get(versions.size() - 2);
    }

    private void load() {

        String filePath = System.getProperty("carbon.home") + File.separator + CONFIG_PATH;
        File file = new File(filePath);
        if (!file.exists()) {
            LOG.warn("os-versions.json not found at: " + filePath + ". Symbolic OS version resolution disabled.");
            return;
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            platformVersions = mapper.readValue(file, new TypeReference<Map<String, List<String>>>() { });
            if (LOG.isDebugEnabled()) {
                Map<String, Integer> counts = new HashMap<>();
                platformVersions.forEach((k, v) -> counts.put(k, v.size()));
                LOG.debug("Loaded OS version registry: " + counts);
            }
        } catch (Exception e) {
            LOG.error("Failed to load os-versions.json from: " + filePath, e);
        }
    }
}
