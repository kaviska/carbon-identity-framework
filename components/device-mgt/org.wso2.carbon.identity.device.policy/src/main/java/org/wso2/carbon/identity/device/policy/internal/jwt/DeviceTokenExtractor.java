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

package org.wso2.carbon.identity.device.policy.internal.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.Device;
import org.wso2.carbon.identity.device.policy.api.constant.DevicePolicyErrorMessage;
import org.wso2.carbon.identity.device.policy.internal.component.DevicePolicyComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.internal.dao.DeviceTokenReplayDAO;
import org.wso2.carbon.identity.device.policy.internal.dao.impl.DeviceTokenReplayDAOImpl;
import org.wso2.carbon.identity.device.policy.internal.util.DevicePolicyDiagnosticLogger;
import org.wso2.carbon.identity.device.policy.internal.util.DevicePolicyExceptionHandler;
import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementServerException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
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
    // A device token is accepted only within this window after its iat, and a small allowance is granted
    // for the device clock running ahead of the server. The expiry stored in the replay store equals
    // iat + this window, so a jti is retained for exactly as long as the token could still be replayed.
    private static final long TOKEN_FRESHNESS_WINDOW_MILLIS = 5 * 60 * 1000L;
    private static final long CLOCK_SKEW_MILLIS = 30 * 1000L;

    private final DevicePolicyDiagnosticLogger diagnosticLogger = new DevicePolicyDiagnosticLogger();

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
            diagnosticLogger.logTokenValidationFailure(null, "X-Device-Token header is missing.");
            throw DevicePolicyExceptionHandler.handleClientException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_MISSING);
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
                diagnosticLogger.logTokenValidationFailure(null, "Device token is not a signed JWT.");
                throw DevicePolicyExceptionHandler.handleClientException(
                        DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_PARSE_FAILED);
            }
            SignedJWT signedJWT = (SignedJWT) parsedJWT;

            String deviceId = (String) signedJWT.getHeader().getCustomParam(DEVICE_ID_PARAM);
            if (deviceId == null || deviceId.trim().isEmpty()) {
                diagnosticLogger.logTokenValidationFailure(null, "Device token header is missing the deviceId.");
                throw DevicePolicyExceptionHandler.handleClientException(
                        DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_MISSING_DEVICE_ID);
            }
            // Strip any stray leading/trailing quotes or backslashes introduced by JWT serialisation bugs.
            deviceId = deviceId.replaceAll("[\"\\\\]+$", "").replaceAll("^[\"\\\\]+", "").trim();

            Device device = DevicePolicyComponentServiceHolder.getInstance()
                    .getDeviceManagementService()
                    .getDeviceById(deviceId, tenantDomain);

            if (device == null) {
                diagnosticLogger.logTokenValidationFailure(deviceId, "Device is not registered.");
                throw DevicePolicyExceptionHandler.handleClientException(
                        DevicePolicyErrorMessage.ERROR_DEVICE_NOT_REGISTERED, deviceId);
            }

            ECPublicKey publicKey = decodePublicKey(device.getPublicKey());

            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                diagnosticLogger.logTokenValidationFailure(deviceId, "Device token signature is invalid.");
                throw DevicePolicyExceptionHandler.handleClientException(
                        DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_SIGNATURE_INVALID, deviceId);
            }

            // Signature is valid, but a valid token can still be replayed. Enforce iat freshness and
            // single-use of the jti before trusting the claims.
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            verifyTokenFreshnessAndUniqueness(deviceId, claimsSet, IdentityTenantUtil.getTenantId(tenantDomain));

            Map<String, Object> deviceData = new HashMap<>();
            claimsSet.getClaims().forEach((key, value) -> {
                if (value != null) {
                    deviceData.put(key, String.valueOf(value));
                }
            });

            diagnosticLogger.logTokenValidationSuccess(deviceId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Device token verified successfully for deviceId: " + deviceId);
            }
            return deviceData;

        } catch (ParseException e) {
            diagnosticLogger.logTokenValidationFailure(null, "Device token could not be parsed.");
            throw DevicePolicyExceptionHandler.handleClientException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_PARSE_FAILED, e);
        } catch (JOSEException e) {
            diagnosticLogger.logTokenValidationFailure(null, "ECDSA verification of the device token failed.");
            throw DevicePolicyExceptionHandler.handleServerException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_ECDSA_VERIFICATION_FAILED, e);
        } catch (DeviceMgtException e) {
            diagnosticLogger.logTokenValidationFailure(null, "Device lookup failed during token validation.");
            throw DevicePolicyExceptionHandler.handleServerException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_LOOKUP_FAILED, e);
        }
    }

    /**
     * Verifies that the device token is fresh and has not been replayed.
     * The token must carry a jti and an iat claim. Tokens whose iat falls outside the freshness window,
     * or whose jti has already been recorded, are rejected. Accepted jti values are persisted so the same
     * token cannot be presented again.
     *
     * @param deviceId  Device ID the token claimed, used for diagnostic correlation.
     * @param claimsSet Parsed JWT claims.
     * @param tenantId  Tenant the device belongs to.
     * @throws PolicyManagementException If a required claim is missing, the token is stale, or it is a replay.
     */
    private void verifyTokenFreshnessAndUniqueness(String deviceId, JWTClaimsSet claimsSet, int tenantId)
            throws PolicyManagementException {

        String jti = claimsSet.getJWTID();
        if (jti == null || jti.trim().isEmpty()) {
            diagnosticLogger.logTokenValidationFailure(deviceId, "Device token is missing the jti claim.");
            throw DevicePolicyExceptionHandler.handleClientException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_MISSING_JTI);
        }

        Date issuedAt = claimsSet.getIssueTime();
        if (issuedAt == null) {
            diagnosticLogger.logTokenValidationFailure(deviceId, "Device token is missing the iat claim.");
            throw DevicePolicyExceptionHandler.handleClientException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_MISSING_IAT);
        }

        long age = System.currentTimeMillis() - issuedAt.getTime();
        // Reject tokens older than the freshness window, or issued in the future beyond the allowed skew.
        if (age > TOKEN_FRESHNESS_WINDOW_MILLIS || age < -CLOCK_SKEW_MILLIS) {
            diagnosticLogger.logTokenValidationFailure(deviceId,
                    "Device token iat is outside the accepted freshness window.");
            throw DevicePolicyExceptionHandler.handleClientException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_EXPIRED,
                    String.valueOf(TOKEN_FRESHNESS_WINDOW_MILLIS / 1000));
        }

        DeviceTokenReplayDAO replayDAO = new DeviceTokenReplayDAOImpl();
        if (replayDAO.isTokenReplayed(jti, tenantId)) {
            diagnosticLogger.logTokenValidationFailure(deviceId,
                    "Device token jti has already been used (replay detected).");
            throw DevicePolicyExceptionHandler.handleClientException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_TOKEN_REPLAYED, jti);
        }

        Timestamp issuedAtTimestamp = new Timestamp(issuedAt.getTime());
        Timestamp expiryTimestamp = new Timestamp(issuedAt.getTime() + TOKEN_FRESHNESS_WINDOW_MILLIS);
        replayDAO.storeToken(jti, tenantId, issuedAtTimestamp, expiryTimestamp);
    }

    private ECPublicKey decodePublicKey(String base64PublicKey)
            throws PolicyManagementServerException {

        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw DevicePolicyExceptionHandler.handleServerException(
                    DevicePolicyErrorMessage.ERROR_DEVICE_PUBLIC_KEY_DECODE_FAILED, e);
        }
    }
}
