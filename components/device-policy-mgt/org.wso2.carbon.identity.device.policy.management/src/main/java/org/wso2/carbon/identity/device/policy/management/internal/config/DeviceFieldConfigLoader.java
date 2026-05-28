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

package org.wso2.carbon.identity.device.policy.management.internal.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.util.Collections;
import java.util.List;

/**
 * Singleton loader for device-fields.json.
 * Reads the config once from $CARBON_HOME/repository/resources/identity/device-policy/device-fields.json
 * and caches it. Used by both DevicePolicyEvaluatorImpl (header mapping) and the metadata API (platform filter).
 */
public class DeviceFieldConfigLoader {

    private static final Log LOG = LogFactory.getLog(DeviceFieldConfigLoader.class);
    private static final String CONFIG_PATH = "repository" + File.separator + "resources"
            + File.separator + "identity" + File.separator + "device-policy"
            + File.separator + "device-fields.json";

    private static volatile DeviceFieldConfigLoader instance;
    private List<DeviceFieldConfig> fields = Collections.emptyList();

    private DeviceFieldConfigLoader() {

        load();
    }

    /**
     * Returns the singleton instance, initializing it on first call.
     */
    public static DeviceFieldConfigLoader getInstance() {

        if (instance == null) {
            synchronized (DeviceFieldConfigLoader.class) {
                if (instance == null) {
                    instance = new DeviceFieldConfigLoader();
                }
            }
        }
        return instance;
    }

    public List<DeviceFieldConfig> getFields() {

        return Collections.unmodifiableList(fields);
    }

    private void load() {

        String filePath = System.getProperty("carbon.home") + File.separator + CONFIG_PATH;
        File file = new File(filePath);
        if (!file.exists()) {
            LOG.warn("device-fields.json not found at: " + filePath + ". Device field config will be empty.");
            return;
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(file);
            fields = mapper.convertValue(root.get("fields"), new TypeReference<List<DeviceFieldConfig>>() { });
            if (LOG.isDebugEnabled()) {
                LOG.debug("Loaded " + fields.size() + " device field configs from: " + filePath);
            }
        } catch (Exception e) {
            LOG.error("Failed to load device-fields.json from: " + filePath, e);
        }
    }
}
