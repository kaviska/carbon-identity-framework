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

package org.wso2.carbon.identity.device.mgt.internal.service.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.mgt.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtClientException;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;
import org.wso2.carbon.identity.device.mgt.api.service.DeviceManagementService;
import org.wso2.carbon.identity.device.mgt.internal.dao.DeviceManagementDAO;
import org.wso2.carbon.identity.device.mgt.internal.dao.impl.DeviceManagementDAOImpl;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Default implementation of {@link DeviceManagementService}.
 */
public class DeviceManagementServiceImpl implements DeviceManagementService {

    private static final Log LOG = LogFactory.getLog(DeviceManagementServiceImpl.class);
    private static final DeviceManagementServiceImpl INSTANCE = new DeviceManagementServiceImpl();

    private final DeviceManagementDAO deviceManagementDAO;

    private DeviceManagementServiceImpl() {

        this.deviceManagementDAO = new DeviceManagementDAOImpl();
    }

    /**
     * Returns the singleton service instance.
     *
     * @return Device management service instance.
     */
    public static DeviceManagementServiceImpl getInstance() {

        return INSTANCE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public RegisteredDevice registerDevice(RegisteredDevice device, String tenantDomain)
            throws DeviceMgtException {

        validateRequiredField(device.getUserId(), "userId");
        validateRequiredField(device.getDeviceName(), "deviceName");
        validateRequiredField(device.getDeviceType(), "deviceType");
        validateRequiredField(device.getPublicKey(), "publicKey");
        validateRequiredField(device.getChallengeUsed(), "challengeUsed");
        validateRequiredField(tenantDomain, "tenantDomain");

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RegisteredDevice deviceToRegister = new RegisteredDevice.Builder()
                .id(UUID.randomUUID().toString())
                .userId(device.getUserId())
                .deviceName(device.getDeviceName())
                .deviceModel(device.getDeviceModel())
                .deviceOs(device.getDeviceOs())
                .deviceType(device.getDeviceType())
                .publicKey(device.getPublicKey())
                .challengeUsed(device.getChallengeUsed())
                .status("ACTIVE")
                .registeredAt(Timestamp.from(Instant.now()))
                .metadata(device.getMetadata())
                .build();

        RegisteredDevice registered = deviceManagementDAO.registerDevice(deviceToRegister, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Device registered with ID: " + registered.getId() + " for user: " + device.getUserId() +
                    " in tenant: " + tenantDomain);
        }
        return registered;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public RegisteredDevice getDeviceById(String deviceId, String tenantDomain)
            throws DeviceMgtException {

        validateRequiredField(deviceId, "deviceId");
        validateRequiredField(tenantDomain, "tenantDomain");
        return deviceManagementDAO.getDeviceById(deviceId, IdentityTenantUtil.getTenantId(tenantDomain));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<RegisteredDevice> getDevicesByUserId(String userId, String tenantDomain)
            throws DeviceMgtException {

        validateRequiredField(userId, "userId");
        validateRequiredField(tenantDomain, "tenantDomain");
        return deviceManagementDAO.getDevicesByUserId(userId, IdentityTenantUtil.getTenantId(tenantDomain));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public RegisteredDevice updateDeviceName(String deviceId, String deviceName, String tenantDomain)
            throws DeviceMgtException {

        validateRequiredField(deviceId, "deviceId");
        validateRequiredField(deviceName, "deviceName");
        validateRequiredField(tenantDomain, "tenantDomain");
        validateDeviceExists(deviceId, tenantDomain);
        return deviceManagementDAO.updateDeviceName(deviceId, deviceName,
                IdentityTenantUtil.getTenantId(tenantDomain));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deleteDevice(String deviceId, String tenantDomain)
            throws DeviceMgtException {

        validateRequiredField(deviceId, "deviceId");
        validateRequiredField(tenantDomain, "tenantDomain");
        validateDeviceExists(deviceId, tenantDomain);
        deviceManagementDAO.deleteDevice(deviceId, IdentityTenantUtil.getTenantId(tenantDomain));
        if (LOG.isDebugEnabled()) {
            LOG.debug("Device deleted with ID: " + deviceId + " in tenant: " + tenantDomain);
        }
    }

    private void validateDeviceExists(String deviceId, String tenantDomain)
            throws DeviceMgtException {

        RegisteredDevice existing = deviceManagementDAO.getDeviceById(deviceId,
                IdentityTenantUtil.getTenantId(tenantDomain));
        if (existing == null) {
            throw new DeviceMgtClientException(
                    ErrorMessage.ERROR_DEVICE_NOT_FOUND.getMessage(),
                    String.format(ErrorMessage.ERROR_DEVICE_NOT_FOUND.getDescription(), deviceId),
                    ErrorMessage.ERROR_DEVICE_NOT_FOUND.getCode());
        }
    }

    private void validateRequiredField(String value, String fieldName)
            throws DeviceMgtClientException {

        if (value == null || value.trim().isEmpty()) {
            throw new DeviceMgtClientException(
                    ErrorMessage.ERROR_INVALID_DEVICE_FIELD.getMessage(),
                    String.format(ErrorMessage.ERROR_INVALID_DEVICE_FIELD.getDescription(), fieldName),
                    ErrorMessage.ERROR_INVALID_DEVICE_FIELD.getCode());
        }
    }
}

