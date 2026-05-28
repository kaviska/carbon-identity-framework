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
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;
import org.wso2.carbon.identity.device.policy.management.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.util.PolicyManagementExceptionHandler;

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
            throw PolicyManagementExceptionHandler.handleClientException(
                    ErrorMessage.ERROR_DEVICE_TOKEN_MISSING);
        }
        return extractFromToken(token, tenantDomain);
    }

    /**
     * Extracts verified device attributes from a raw JWT string.
     * Use this when the token has already been extracted from a query param or header.
     *
     * @param token        Raw JWT string to parse and verify.
     * @param tenantDomain Tenant domain used for device lookup.
     * @return Map of device field names to their values from verified JWT claims.
     * @throws PolicyManagementException If the token is invalid or signature verification fails.
     */
    public Map<String, Object> extractFromToken(String token, String tenantDomain)
            throws PolicyManagementException {

        try {
            JWT parsedJWT = JWTParser.parse(token);
            if (!(parsedJWT instanceof SignedJWT)) {
                throw PolicyManagementExceptionHandler.handleClientException(
                        ErrorMessage.ERROR_DEVICE_TOKEN_PARSE_FAILED);
            }
            SignedJWT signedJWT = (SignedJWT) parsedJWT;

            String deviceId = (String) signedJWT.getHeader().getCustomParam(DEVICE_ID_PARAM);
            if (deviceId == null || deviceId.trim().isEmpty()) {
                throw PolicyManagementExceptionHandler.handleClientException(
                        ErrorMessage.ERROR_DEVICE_TOKEN_MISSING_DEVICE_ID);
            }
            // Strip any stray leading/trailing quotes or backslashes introduced by JWT serialisation bugs.
            deviceId = deviceId.replaceAll("[\"\\\\]+$", "").replaceAll("^[\"\\\\]+", "").trim();

            RegisteredDevice device = DevicePolicyMgtComponentServiceHolder.getInstance()
                    .getDeviceManagementService()
                    .getDeviceById(deviceId, tenantDomain);

            if (device == null) {
                throw PolicyManagementExceptionHandler.handleClientException(
                        ErrorMessage.ERROR_DEVICE_NOT_REGISTERED, deviceId);
            }

            ECPublicKey publicKey = decodePublicKey(device.getPublicKey());

            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                throw PolicyManagementExceptionHandler.handleClientException(
                        ErrorMessage.ERROR_DEVICE_TOKEN_SIGNATURE_INVALID, deviceId);
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
            throw PolicyManagementExceptionHandler.handleClientException(
                    ErrorMessage.ERROR_DEVICE_TOKEN_PARSE_FAILED, e);
        } catch (JOSEException e) {
            throw PolicyManagementExceptionHandler.handleServerException(
                    ErrorMessage.ERROR_DEVICE_ECDSA_VERIFICATION_FAILED, e);
        } catch (DeviceMgtException e) {
            throw PolicyManagementExceptionHandler.handleServerException(
                    ErrorMessage.ERROR_DEVICE_LOOKUP_FAILED, e);
        }
    }

    private ECPublicKey decodePublicKey(String base64PublicKey)
            throws PolicyManagementServerException {

        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw PolicyManagementExceptionHandler.handleServerException(
                    ErrorMessage.ERROR_DEVICE_PUBLIC_KEY_DECODE_FAILED, e);
        }
    }
}
