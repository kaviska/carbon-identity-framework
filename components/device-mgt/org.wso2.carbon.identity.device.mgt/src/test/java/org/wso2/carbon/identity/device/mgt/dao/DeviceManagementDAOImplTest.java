/*
* Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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
* KIND, either express or implied. See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.identity.device.mgt.dao;

import org.h2.jdbcx.JdbcDataSource;
import org.h2.tools.RunScript;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;
import org.wso2.carbon.identity.device.mgt.internal.dao.impl.DeviceManagementDAOImpl;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import javax.sql.DataSource;

import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for {@link DeviceManagementDAOImpl}.
 */
public class DeviceManagementDAOImplTest {

    private static final int TENANT_ID = -1234;
    private static final String TEST_USER_ID = "alice@example.com";

    private DeviceManagementDAOImpl deviceManagementDAO;
    private MockedStatic<IdentityDatabaseUtil> identityDatabaseUtil;
    private String createdDeviceId;

    /**
     * Initializes test dependencies.
     */
    @BeforeClass
    public void setUp() throws Exception {

        DataSource dataSource = initializeDatasource();
        identityDatabaseUtil = mockStatic(IdentityDatabaseUtil.class);
        identityDatabaseUtil.when(IdentityDatabaseUtil::getDataSource).thenReturn(dataSource);
        deviceManagementDAO = new DeviceManagementDAOImpl();
    }

    /**
     * Clears mocked static resources.
     */
    @AfterClass
    public void tearDown() {

        identityDatabaseUtil.close();
    }

    /**
     * Tests registering a device.
     *
     * @throws DeviceMgtException If the DAO operation fails.
     */
    @Test(priority = 1)
    public void testRegisterDevice() throws DeviceMgtException {

        RegisteredDevice device = buildDevice(UUID.randomUUID().toString(), "Alice Phone", "ACTIVE");
        RegisteredDevice result = deviceManagementDAO.registerDevice(device, TENANT_ID);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getId(), device.getId());
        Assert.assertEquals(result.getDeviceName(), "Alice Phone");
        Assert.assertEquals(result.getStatus(), "ACTIVE");

        createdDeviceId = result.getId();
    }

    /**
     * Tests retrieving a device by id.
     *
     * @throws DeviceMgtException If the DAO operation fails.
     */
    @Test(priority = 2, dependsOnMethods = {"testRegisterDevice"})
    public void testGetDeviceById() throws DeviceMgtException {

        RegisteredDevice result = deviceManagementDAO.getDeviceById(createdDeviceId, TENANT_ID);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getId(), createdDeviceId);
        Assert.assertEquals(result.getUserId(), TEST_USER_ID);
    }

    /**
     * Tests retrieving a non-existing device by id.
     *
     * @throws DeviceMgtException If the DAO operation fails.
     */
    @Test(priority = 3)
    public void testGetDeviceByIdNotFound() throws DeviceMgtException {

        RegisteredDevice result = deviceManagementDAO.getDeviceById(UUID.randomUUID().toString(), TENANT_ID);
        Assert.assertNull(result);
    }

    /**
     * Tests retrieving active devices by user id.
     *
     * @throws DeviceMgtException If the DAO operation fails.
     */
    @Test(priority = 4, dependsOnMethods = {"testRegisterDevice"})
    public void testGetDevicesByUserIdOnlyActive() throws DeviceMgtException {

        RegisteredDevice revokedDevice = buildDevice(UUID.randomUUID().toString(), "Old Device", "REVOKED");
        deviceManagementDAO.registerDevice(revokedDevice, TENANT_ID);

        List<RegisteredDevice> devices = deviceManagementDAO.getDevicesByUserId(TEST_USER_ID, TENANT_ID);

        Assert.assertEquals(devices.size(), 1);
        Assert.assertEquals(devices.get(0).getStatus(), "ACTIVE");
        Assert.assertEquals(devices.get(0).getId(), createdDeviceId);
    }

    /**
     * Tests updating a device name.
     *
     * @throws DeviceMgtException If the DAO operation fails.
     */
    @Test(priority = 5, dependsOnMethods = {"testRegisterDevice"})
    public void testUpdateDeviceName() throws DeviceMgtException {

        RegisteredDevice updated = deviceManagementDAO.updateDeviceName(createdDeviceId, "Alice Updated", TENANT_ID);

        Assert.assertNotNull(updated);
        Assert.assertEquals(updated.getDeviceName(), "Alice Updated");
    }

    /**
     * Tests deleting a device.
     *
     * @throws DeviceMgtException If the DAO operation fails.
     */
    @Test(priority = 6, dependsOnMethods = {"testRegisterDevice"})
    public void testDeleteDevice() throws DeviceMgtException {

        deviceManagementDAO.deleteDevice(createdDeviceId, TENANT_ID);
        RegisteredDevice afterDelete = deviceManagementDAO.getDeviceById(createdDeviceId, TENANT_ID);

        Assert.assertNull(afterDelete);
    }

    private RegisteredDevice buildDevice(String id, String deviceName, String status) {

        return new RegisteredDevice.Builder()
                .id(id)
                .userId(TEST_USER_ID)
                .deviceName(deviceName)
                .deviceModel("iPhone 15 Pro")
                .deviceOs("iOS 17.4")
                .deviceType("MOBILE")
                .publicKey("base64-public-key-" + id)
                .challengeUsed("challenge-" + id)
                .status(status)
                .registeredAt(Timestamp.from(Instant.now()))
                .metadata("{\"label\":\"primary\"}")
                .build();
    }

    private DataSource initializeDatasource() throws Exception {

        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setUser("sa");
        dataSource.setPassword("sa");
        dataSource.setURL("jdbc:h2:mem:device_mgt_db;DB_CLOSE_DELAY=-1");

        Path scriptPath = Path.of(System.getProperty("user.dir"), "src", "test", "resources", "dbscripts", "h2.sql");
        try (java.sql.Connection connection = dataSource.getConnection()) {
            RunScript.execute(connection, Files.newBufferedReader(scriptPath));
        }
        return dataSource;
    }
}


