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

package org.wso2.carbon.identity.device.policy.internal.service.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.MockedStatic;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.device.policy.api.constant.DevicePolicyErrorMessage;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyServerException;
import org.wso2.carbon.identity.device.policy.internal.config.DeviceFieldConfigLoader;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class DeviceFieldMetadataServiceImplTest {

    @BeforeClass
    public void setUpClass() {

        System.setProperty("carbon.home", System.getProperty("user.dir") + "/src/test/resources");
    }

    @Test
    public void testGetFieldApplicablePlatformsWhenNotLoaded() throws Exception {

        // Ensure instance field is set to null via reflection
        Field instanceField = DeviceFieldConfigLoader.class.getDeclaredField("instance");
        instanceField.setAccessible(true);
        DeviceFieldConfigLoader oldInstance = (DeviceFieldConfigLoader) instanceField.get(null);
        instanceField.set(null, null);

        DeviceFieldMetadataServiceImpl service = new DeviceFieldMetadataServiceImpl();

        try {
            service.getFieldApplicablePlatforms();
            fail("Expected DevicePolicyServerException when loader is not initialized.");
        } catch (DevicePolicyServerException e) {
            assertEquals(e.getErrorCode(), DevicePolicyErrorMessage.ERROR_DEVICE_FIELD_CONFIG_NOT_LOADED.getCode());
        } finally {
            instanceField.set(null, oldInstance);
        }
    }

    @Test
    public void testGetFieldApplicablePlatformsSuccess() throws Exception {

        Log mockLog = mock(Log.class);
        when(mockLog.isDebugEnabled()).thenReturn(false);
        try (MockedStatic<LogFactory> mockedLogFactory = mockStatic(LogFactory.class)) {
            mockedLogFactory.when(() -> LogFactory.getLog(DeviceFieldConfigLoader.class)).thenReturn(mockLog);
            DeviceFieldConfigLoader.load();
        }

        DeviceFieldMetadataServiceImpl service = new DeviceFieldMetadataServiceImpl();
        Map<String, List<String>> result = service.getFieldApplicablePlatforms();

        assertNotNull(result);
        assertTrue(result.containsKey("device_model"));
        assertEquals(result.get("device_model").size(), 2);
    }
}
