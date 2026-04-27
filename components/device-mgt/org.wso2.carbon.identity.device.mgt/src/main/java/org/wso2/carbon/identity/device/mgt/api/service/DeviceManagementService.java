package org.wso2.carbon.identity.device.mgt.api.service;

import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.DeviceRegistrationInitiation;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;

import java.util.List;

public interface DeviceManagementService {

    /**
     * Phase 1 of the two-phase registration protocol.
     * Generates a cryptographically random challenge and stores it in the distributed cache
     * keyed by the returned registrationId. The client SDK must sign the challenge with its
     * private key and return the signature in Phase 2.
     *
     * @param username     Username of the registering user.
     * @param tenantDomain Tenant domain.
     * @return DeviceRegistrationInitiation containing registrationId and challenge (base64url).
     */
    DeviceRegistrationInitiation initiateDeviceRegistration(String username, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Phase 2 of the two-phase registration protocol.
     * Retrieves the cached registration context by registrationId, verifies the ECDSA signature
     * (SHA256withECDSA) against the stored challenge, persists the device, and clears the cache.
     *
     * @param registrationId  Opaque token returned by initiateDeviceRegistration.
     * @param publicKey       Base64-encoded EC public key in X.509/SubjectPublicKeyInfo DER format.
     * @param signature       Base64-encoded ECDSA signature over the challenge bytes.
     * @param deviceName      Human-readable name for the device.
     * @param deviceModel     Hardware model string (nullable).
     * @param metadata        Optional JSON string for extensible attributes (nullable).
     * @param tenantDomain    Tenant domain.
     * @return The persisted RegisteredDevice with server-assigned id and registeredAt.
     */
    RegisteredDevice completeDeviceRegistration(
            String registrationId,
            String publicKey,
            String signature,
            String deviceName,
            String deviceModel,
            String metadata,
            String tenantDomain) throws DeviceMgtException;

    /**
     * Verifies the device registration challenge-response without persisting to the database.
     * Used during registration flows where the user does not yet have a provisioned userId —
     * the caller stores the returned object in the flow context and defers the DB write to
     * {@link #persistDevice(RegisteredDevice, String)} once UserProvisioningExecutor has run.
     *
     * @param registrationId Opaque token returned by initiateDeviceRegistration.
     * @param publicKey      Base64-encoded EC public key (X.509/SubjectPublicKeyInfo DER).
     * @param signature      Base64-encoded ECDSA signature over the challenge bytes.
     * @param deviceName     Human-readable name for the device.
     * @param deviceModel    Hardware model string (nullable).
     * @param metadata       Optional JSON string for extensible attributes (nullable).
     * @param tenantDomain   Tenant domain.
     * @return A RegisteredDevice whose userId is a placeholder — caller must replace it with the
     *         real userId before calling {@link #persistDevice(RegisteredDevice, String)}.
     */
    RegisteredDevice verifyDeviceRegistration(
            String registrationId,
            String publicKey,
            String signature,
            String deviceName,
            String deviceModel,
            String metadata,
            String tenantDomain) throws DeviceMgtException;

    /**
     * Persists a pre-verified {@link RegisteredDevice} to the database.
     * Counterpart to {@link #verifyDeviceRegistration}: call this after replacing the placeholder
     * userId with the real provisioned userId.
     *
     * @param device       The verified device to persist.
     * @param tenantDomain Tenant domain.
     */
    void persistDevice(RegisteredDevice device, String tenantDomain) throws DeviceMgtException;

    /**
     * Retrieves a device by its UUID.
     *
     * @param deviceId     UUID of the device (IDN_REGISTERED_DEVICE.ID).
     * @param tenantDomain Tenant domain.
     * @return The RegisteredDevice, or null if not found.
     */
    RegisteredDevice getDeviceById(String deviceId, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Retrieves all ACTIVE devices registered by a user.
     *
     * @param userId       WSO2 user identifier.
     * @param tenantDomain Tenant domain.
     * @return List of active RegisteredDevice objects. Empty list if none found.
     */
    List<RegisteredDevice> getDevicesByUserId(String userId, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Updates the display name of a device.
     *
     * @param deviceId     UUID of the device.
     * @param deviceName   New name for the device.
     * @param tenantDomain Tenant domain.
     * @return The updated RegisteredDevice.
     */
    RegisteredDevice updateDeviceName(String deviceId, String deviceName, String tenantDomain)
            throws DeviceMgtException;

    /**
     * Deletes (hard delete) a device registration record.
     *
     * @param deviceId     UUID of the device.
     * @param tenantDomain Tenant domain.
     */
    void deleteDevice(String deviceId, String tenantDomain)
            throws DeviceMgtException;
}