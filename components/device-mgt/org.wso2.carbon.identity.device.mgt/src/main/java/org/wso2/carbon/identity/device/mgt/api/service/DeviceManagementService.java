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

package org.wso2.carbon.identity.device.mgt.api.service;

import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;

import java.util.List;

/**
 * Public service API for registered device management.
 */
public interface DeviceManagementService {

    /**
     * Registers a new device for a user.
     *
     * @param device Device to register.
     * @param tenantDomain Tenant domain.
     * @return Persisted device with server-assigned fields.
     * @throws DeviceMgtException If registration fails.
     */
    RegisteredDevice registerDevice(RegisteredDevice device, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Retrieves a device by its identifier.
     *
     * @param deviceId Device identifier.
     * @param tenantDomain Tenant domain.
     * @return Registered device or {@code null}.
     * @throws DeviceMgtException If retrieval fails.
     */
    RegisteredDevice getDeviceById(String deviceId, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Retrieves all active devices for a user.
     *
     * @param userId User identifier.
     * @param tenantDomain Tenant domain.
     * @return List of active registered devices.
     * @throws DeviceMgtException If retrieval fails.
     */
    List<RegisteredDevice> getDevicesByUserId(String userId, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Updates the display name of a device.
     *
     * @param deviceId Device identifier.
     * @param deviceName Device display name.
     * @param tenantDomain Tenant domain.
     * @return Updated registered device.
     * @throws DeviceMgtException If update fails.
     */
    RegisteredDevice updateDeviceName(String deviceId, String deviceName, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Deletes a device registration.
     *
     * @param deviceId Device identifier.
     * @param tenantDomain Tenant domain.
     * @throws DeviceMgtException If deletion fails.
     */
    void deleteDevice(String deviceId, String tenantDomain)
            throws DeviceMgtException;
}

