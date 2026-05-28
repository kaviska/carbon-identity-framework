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

package org.wso2.carbon.identity.device.mgt.internal.dao;

import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;

import java.util.List;

/**
 * DAO contract for registered device persistence.
 */
public interface DeviceManagementDAO {

    /**
     * Persists a new device.
     *
     * @param device Device to persist.
     * @param tenantId Tenant identifier.
     * @return Persisted device.
     * @throws DeviceMgtException If persistence fails.
     */
    RegisteredDevice registerDevice(RegisteredDevice device, int tenantId)
            throws DeviceMgtException;

    /**
     * Finds a device by id.
     *
     * @param deviceId Device identifier.
     * @param tenantId Tenant identifier.
     * @return Device or {@code null}.
     * @throws DeviceMgtException If retrieval fails.
     */
    RegisteredDevice getDeviceById(String deviceId, int tenantId)
            throws DeviceMgtException;

    /**
     * Finds all active devices by user id.
     *
     * @param userId User identifier.
     * @param tenantId Tenant identifier.
     * @return Active devices.
     * @throws DeviceMgtException If retrieval fails.
     */
    List<RegisteredDevice> getDevicesByUserId(String userId, int tenantId)
            throws DeviceMgtException;

    /**
     * Finds all devices registered in the tenant.
     *
     * @param tenantId Tenant identifier.
     * @return All devices in the tenant.
     * @throws DeviceMgtException If retrieval fails.
     */
    List<RegisteredDevice> getAllDevices(int tenantId)
            throws DeviceMgtException;

    /**
     * Updates the name of a device.
     *
     * @param deviceId Device identifier.
     * @param deviceName Device name.
     * @param tenantId Tenant identifier.
     * @return Updated device.
     * @throws DeviceMgtException If update fails.
     */
    RegisteredDevice updateDeviceName(String deviceId, String deviceName, int tenantId)
            throws DeviceMgtException;

    /**
     * Deletes a device.
     *
     * @param deviceId Device identifier.
     * @param tenantId Tenant identifier.
     * @throws DeviceMgtException If deletion fails.
     */
    void deleteDevice(String deviceId, int tenantId)
            throws DeviceMgtException;

}

