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

package org.wso2.carbon.identity.device.policy.management.internal.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Extracts and verifies device attribute data from a signed JWT in the X-Device-Token header.
 * The JWT header must contain a deviceId custom parameter used to look up the registered public key.
 * Signature is verified using ECDSA before claims are returned.
 */
public class DeviceTokenExtractor {

    private static final Log LOG = LogFactory.getLog(DeviceTokenExtractor.class);
    private static final String DEVICE_TOKEN_HEADER = "X-Device-Token";
    private static final String DEVICE_ID_PARAM = "deviceId";

    /**
     * Extracts verified device attributes from the X-Device-Token JWT in the request.
     *
     * @param request      The HTTP request containing the X-Device-Token header.
     * @param tenantDomain Tenant domain used for device lookup.
     * @return Map of device field names to their values from verified JWT claims.
     * @throws PolicyManagementException If the token is missing, invalid, or signature verification fails.
     */
    public Map<String, Object> extract(HttpServletRequest request, String tenantDomain)
            throws PolicyManagementException {

        String token = request.getHeader(DEVICE_TOKEN_HEADER);
        if (token == null || token.trim().isEmpty()) {
            throw new PolicyManagementServerException(
                    "Device token missing.",
                    "X-Device-Token header is not present in the request.",
                    "DPM-60010");
        }

        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(token);

            String deviceId = (String) signedJWT.getHeader().getCustomParam(DEVICE_ID_PARAM);
            if (deviceId == null || deviceId.trim().isEmpty()) {
                throw new PolicyManagementServerException(
                        "Device token invalid.",
                        "deviceId is missing from the JWT header.",
                        "DPM-60011");
            }
            // Strip any stray leading/trailing quotes or backslashes introduced by JWT serialisation bugs.
            deviceId = deviceId.replaceAll("[\"\\\\]+$", "").replaceAll("^[\"\\\\]+", "").trim();

            RegisteredDevice device = DevicePolicyMgtComponentServiceHolder.getInstance()
                    .getDeviceManagementService()
                    .getDeviceById(deviceId, tenantDomain);

            if (device == null) {
                throw new PolicyManagementServerException(
                        "Device not registered.",
                        "No registered device found for deviceId: " + deviceId,
                        "DPM-60012");
            }

            ECPublicKey publicKey = decodePublicKey(device.getPublicKey());

            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                throw new PolicyManagementServerException(
                        "Device token signature invalid.",
                        "JWT signature verification failed for deviceId: " + deviceId,
                        "DPM-60013");
            }

            Map<String, Object> deviceData = new HashMap<>();
            signedJWT.getJWTClaimsSet().getClaims().forEach((key, value) -> {
                if (value != null) {
                    deviceData.put(key, String.valueOf(value));
                }
            });

            if (LOG.isDebugEnabled()) {
                LOG.debug("Device token verified successfully for deviceId: " + deviceId);
            }
            return deviceData;

        } catch (ParseException e) {
            throw new PolicyManagementServerException(
                    "Device token invalid.",
                    "Failed to parse X-Device-Token JWT: " + e.getMessage(),
                    "DPM-60014", e);
        } catch (JOSEException e) {
            throw new PolicyManagementServerException(
                    "Device token verification failed.",
                    "ECDSA verification error: " + e.getMessage(),
                    "DPM-60015", e);
        } catch (DeviceMgtException e) {
            throw new PolicyManagementServerException(
                    "Device lookup failed.",
                    "Error retrieving device from registry: " + e.getMessage(),
                    "DPM-60016", e);
        }
    }

    private ECPublicKey decodePublicKey(String base64PublicKey)
            throws PolicyManagementServerException {

        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new PolicyManagementServerException(
                    "Device public key invalid.",
                    "Failed to decode EC public key from registered device: " + e.getMessage(),
                    "DPM-60017", e);
        }
    }
}
