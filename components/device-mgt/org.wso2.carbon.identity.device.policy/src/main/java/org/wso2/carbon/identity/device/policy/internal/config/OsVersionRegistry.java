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
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Registry that loads os-versions.json and resolves symbolic OS version names.
 * Symbolic names: LATEST_ANDROID, SECOND_LATEST_ANDROID, LATEST_IOS, SECOND_LATEST_IOS,
 * LATEST_MACOS, SECOND_LATEST_MACOS, LATEST_WINDOWS, SECOND_LATEST_WINDOWS.
 * Must be initialised once at bundle activation via {@link #load()} before any call to
 * {@link #getInstance()}. If the config file is absent or unparseable, {@link #load()} throws
 * {@link DevicePolicyConfigException}, causing activation to fail loudly.
 */
public class OsVersionRegistry implements SymbolicValueResolver {

    private static final Log LOG = LogFactory.getLog(OsVersionRegistry.class);
    private static final String CONFIG_PATH = "repository" + File.separator + "resources"
            + File.separator + "identity" + File.separator + "device-policy"
            + File.separator + "os-versions.json";

    private static volatile OsVersionRegistry instance;

    private final Map<String, List<String>> platformVersions;

    private OsVersionRegistry(Map<String, List<String>> platformVersions) {

        this.platformVersions = platformVersions;
    }

    /**
     * Loads os-versions.json from the IS config directory and initialises the singleton.
     * Must be called once from the OSGi component {@code @Activate} method.
     *
     * @throws DevicePolicyConfigException If the file is absent or cannot be parsed.
     */
    public static void load() throws DevicePolicyConfigException {

        String filePath = CarbonUtils.getCarbonHome() + File.separator + CONFIG_PATH;
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            throw new DevicePolicyConfigException("os-versions.json not found at: " + file.getAbsolutePath());
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, List<String>> loaded =
                    mapper.readValue(file, new TypeReference<Map<String, List<String>>>() { });
            instance = new OsVersionRegistry(loaded);
            if (LOG.isDebugEnabled()) {
                Map<String, Integer> counts = new HashMap<>();
                loaded.forEach((k, v) -> counts.put(k, v.size()));
                LOG.debug("Loaded OS version registry: " + counts);
            }
        } catch (IOException e) {
            throw new DevicePolicyConfigException(
                    "Failed to parse os-versions.json from: " + filePath, e);
        }
    }

    /**
     * Returns the singleton instance initialised by {@link #load()}.
     *
     * @return The loaded {@link OsVersionRegistry}.
     */
    public static OsVersionRegistry getInstance() {

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

    /**
     * Returns an unmodifiable view of the platform-to-versions map.
     *
     * @return Map of platform name to ordered list of version strings.
     */
    public Map<String, List<String>> getPlatformVersions() {

        return Collections.unmodifiableMap(platformVersions);
    }
}
