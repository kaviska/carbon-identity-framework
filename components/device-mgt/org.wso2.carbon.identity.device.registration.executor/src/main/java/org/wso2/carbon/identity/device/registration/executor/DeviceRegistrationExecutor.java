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

package org.wso2.carbon.identity.device.registration.executor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.device.mgt.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtClientException;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.DeviceRegistrationInitiation;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;
import org.wso2.carbon.identity.device.mgt.api.service.DeviceManagementService;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.rule.DevicePolicyEvaluator;
import org.wso2.carbon.identity.device.registration.executor.internal.DeviceRegistrationExecutorDataHolder;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;

/**
 * Flow executor for generic device registration.
 *
 * Implements a two-phase challenge-response protocol:
 *   Phase 1 — first call, no registrationId in context:
 *     Generates challenge via DeviceManagementService.initiateDeviceRegistration(), stores
 *     registrationId in FlowExecutionContext.properties, returns STATUS_CLIENT_INPUT_REQUIRED
 *     so the SDK can sign the challenge natively.
 *
 *   Phase 2 — second call, registrationId present in context:
 *     Verifies the ECDSA signature. If an optional policyName is configured in executor
 *     metadata, evaluates device compliance before persisting. In REGISTRATION flows the
 *     verified device is stored in context for RegistrationFlowCompletionListener to persist
 *     after UserProvisioningExecutor assigns the real userId. In other flows it is persisted
 *     immediately.
 */
public class DeviceRegistrationExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(DeviceRegistrationExecutor.class);

    public static final String EXECUTOR_NAME = "DeviceRegistrationExecutor";

    private static final String CTX_REGISTRATION_ID = "device.registration.id";

    // Holds the verified-but-not-yet-persisted RegisteredDevice in REGISTRATION flows.
    // RegistrationFlowCompletionListener reads this after UserProvisioningExecutor has run.
    public static final String CTX_DEVICE_REGISTRATION = "device.registration.data";

    private static final String PROP_REGISTRATION_ID = "registrationId";
    private static final String PROP_CHALLENGE = "challenge";

    private static final String FIELD_PUBLIC_KEY   = "publicKey";
    private static final String FIELD_SIGNATURE    = "signature";
    private static final String FIELD_DEVICE_MODEL = "deviceModel";
    private static final String FIELD_METADATA     = "metadata";
    private static final String FIELD_DEVICE_DATA  = "deviceData";

    private static final String META_POLICY_NAME = "policyName";

    @Override
    public String getName() {
        return EXECUTOR_NAME;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) throws FlowEngineException {

        String registrationId = (String) context.getProperty(CTX_REGISTRATION_ID);

        if (registrationId == null) {
            return initiateRegistration(context);
        }
        return completeRegistration(context, registrationId);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) throws FlowEngineException {
        // Cache entry expires automatically via TTL; nothing to undo.
        return new ExecutorResponse(STATUS_COMPLETE);
    }

    @Override
    public List<String> getInitiationData() {
        return Collections.emptyList();
    }

    /**
     * Reads the optional policyName from executor metadata configured by the admin.
     * Returns null if not configured, which skips policy evaluation entirely.
     */
    private String resolvePolicyName(FlowExecutionContext context) {

        NodeConfig node = context.getCurrentNode();
        if (node == null || node.getExecutorConfig() == null) {
            return null;
        }
        Map<String, String> meta = node.getExecutorConfig().getMetadata();
        if (meta == null) {
            return null;
        }
        String policyName = meta.get(META_POLICY_NAME);
        return isBlank(policyName) ? null : policyName;
    }

    private ExecutorResponse initiateRegistration(FlowExecutionContext context) {

        DeviceManagementService service =
                DeviceRegistrationExecutorDataHolder.getInstance().getDeviceManagementService();
        try {
            // Use real UUID if already available (invite flow); fall back to username (self-registration).
            String userId = context.getFlowUser().getUserId();
            String username = isNotBlank(userId) ? userId : context.getFlowUser().getUsername();
            if (isBlank(username)) {
                ExecutorResponse response = new ExecutorResponse();
                response.setResult(STATUS_ERROR);
                response.setErrorCode(ErrorMessage.ERROR_USER_NOT_IDENTIFIED.getCode());
                response.setErrorMessage(ErrorMessage.ERROR_USER_NOT_IDENTIFIED.getMessage());
                response.setErrorDescription(ErrorMessage.ERROR_USER_NOT_IDENTIFIED.getDescription());
                return response;
            }
            // Set username on thread-local context so downstream services (audit, events) can read it.
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(username);

            DeviceRegistrationInitiation initiation =
                    service.initiateDeviceRegistration(username, context.getTenantDomain());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Device registration initiated for user: " + username
                        + " registrationId: " + initiation.getRegistrationId());
            }

            Map<String, String> additionalInfo = new HashMap<>();
            additionalInfo.put(PROP_REGISTRATION_ID, initiation.getRegistrationId());
            additionalInfo.put(PROP_CHALLENGE, initiation.getChallenge());


            Map<String, Object> contextProperties = new HashMap<>();
            contextProperties.put(CTX_REGISTRATION_ID, initiation.getRegistrationId());

            // If a compliance policy is configured, tell the SDK to send device attributes
            // as a single nested object under the "deviceData" key. The SDK bundles whatever
            // device attributes it has into that object; the server parses it in Phase 2.
            List<String> requiredFields = new ArrayList<>(
                    Arrays.asList(FIELD_PUBLIC_KEY, FIELD_SIGNATURE));
            List<String> optionalFields = new ArrayList<>(
                    Arrays.asList(FIELD_DEVICE_MODEL, FIELD_METADATA));
            String policyName = resolvePolicyName(context);
            if (policyName != null) {
                requiredFields.add(FIELD_DEVICE_DATA);
            }

            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_CLIENT_INPUT_REQUIRED);
            response.setRequiredData(requiredFields);
            response.setOptionalData(optionalFields);
            response.setAdditionalInfo(additionalInfo);
            response.setContextProperty(contextProperties);
            return response;

        } catch (DeviceMgtException e) {
            LOG.error("Error initiating device registration in tenant: "
                    + context.getTenantDomain(), e);
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorCode(e.getErrorCode());
            response.setErrorMessage(e.getMessage());
            response.setErrorDescription(e.getDescription());
            return response;
        }
    }

    private ExecutorResponse completeRegistration(FlowExecutionContext context,
            String registrationId) {

        DeviceManagementService service =
                DeviceRegistrationExecutorDataHolder.getInstance().getDeviceManagementService();
        try {
            Map<String, String> input = context.getUserInputData();
            String deviceModel = input.get(FIELD_DEVICE_MODEL);
            String deviceName = buildDeviceName(context, deviceModel);

            // Step 1: Verify signature and clear registration cache entry.
            RegisteredDevice verified = service.verifyDeviceRegistration(
                    registrationId,
                    input.get(FIELD_PUBLIC_KEY),
                    input.get(FIELD_SIGNATURE),
                    deviceName,
                    deviceModel,
                    input.get(FIELD_METADATA),
                    context.getTenantDomain());

            // Step 2: Policy compliance check (skipped when policyName not configured).
            String policyName = resolvePolicyName(context);
            if (policyName != null) {
                if (isBlank(input.get(FIELD_DEVICE_DATA))) {
                    ExecutorResponse response = new ExecutorResponse();
                    response.setResult(STATUS_USER_ERROR);
                    response.setErrorCode(ErrorMessage.ERROR_DEVICE_DATA_REQUIRED.getCode());
                    response.setErrorMessage(ErrorMessage.ERROR_DEVICE_DATA_REQUIRED.getMessage());
                    response.setErrorDescription(ErrorMessage.ERROR_DEVICE_DATA_REQUIRED.getDescription());
                    return response;
                }
                ExecutorResponse policyResult = evaluatePolicy(policyName, context);
                if (policyResult != null) {
                    return policyResult;
                }
            }

            if ("REGISTRATION".equals(context.getFlowType())) {
                // userId is not yet assigned — UserProvisioningExecutor runs at END after this.
                // Defer the DB write to RegistrationFlowCompletionListener, which fires after
                // COMPLETE and has the real userId from FlowUser.
                ExecutorResponse response = new ExecutorResponse();
                response.setResult(STATUS_COMPLETE);
                Map<String, Object> ctxProps = new HashMap<>();
                ctxProps.put(CTX_DEVICE_REGISTRATION, verified);
                response.setContextProperty(ctxProps);
                return response;
            }

            // Non-registration flow: userId already exists, persist immediately.
            service.persistDevice(verified, context.getTenantDomain());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Device registration completed for registrationId: " + registrationId);
            }
            return new ExecutorResponse(STATUS_COMPLETE);

        } catch (DeviceMgtClientException e) {
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_USER_ERROR);
            response.setErrorCode(e.getErrorCode());
            response.setErrorMessage(e.getMessage());
            response.setErrorDescription(e.getDescription());
            return response;
        } catch (DeviceMgtException e) {
            LOG.error("Error completing device registration for registrationId: "
                    + registrationId, e);
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorCode(e.getErrorCode());
            response.setErrorMessage(e.getMessage());
            response.setErrorDescription(e.getDescription());
            return response;
        }
    }

    /**
     * Builds a device name automatically from the authenticated username and optional device model.
     * Format: "{username}'s {deviceModel}" or "{username}'s Device" when model is absent.
     */
    private String buildDeviceName(FlowExecutionContext context, String deviceModel) {

        String userId = context.getFlowUser().getUserId();
        String username = isNotBlank(userId) ? userId : context.getFlowUser().getUsername();
        String base = isNotBlank(username) ? username : "Unknown";
        return isNotBlank(deviceModel) ? base + "'s " + deviceModel : base + "'s Device";
    }

    /**
     * Extracts device attributes from the SDK's Phase 2 input.
     * The SDK sends all device attributes as a JSON object under the {@code "deviceData"} key.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseDeviceData(Map<String, String> input) {

        Map<String, Object> deviceData = new HashMap<>();
        if (input == null) {
            return deviceData;
        }
        String json = input.get(FIELD_DEVICE_DATA);
        if (isBlank(json)) {
            return deviceData;
        }
        try {
            com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>> typeRef =
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() { };
            Map<String, Object> parsed = new com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue(json, typeRef);
            deviceData.putAll(parsed);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            LOG.error("Failed to parse deviceData JSON submitted by SDK.", e);
        }
        return deviceData;
    }

    /**
     * Evaluates device policy compliance using attributes submitted by the SDK in Phase 2.
     * Accepts a comma-separated list of policy names and applies OR logic — the device is
     * considered compliant if it satisfies at least one policy. This mirrors the adaptive
     * auth script pattern where platform-specific policies are evaluated together.
     *
     * <p>Examples:
     * <ul>
     *   <li>{@code "iOSPolicy-01"} — single policy, must pass.</li>
     *   <li>{@code "iOSPolicy-01,AndroidPolicy-01"} — passes if either platform policy passes.</li>
     * </ul>
     *
     * @return null if the device is compliant with at least one policy, or an error
     *         ExecutorResponse listing per-policy failures if all policies fail.
     */
    private ExecutorResponse evaluatePolicy(String policyNames, FlowExecutionContext context) {

        DevicePolicyEvaluator evaluator = new DevicePolicyEvaluator();
        Map<String, Object> deviceData = parseDeviceData(context.getUserInputData());
        // Fill any missing fields so the rule engine always sees a complete map.
        for (String fieldName : evaluator.getFieldNames()) {
            deviceData.putIfAbsent(fieldName, "not_available");
        }

        String[] policies = policyNames.split(",");
        // LinkedHashMap preserves insertion order for deterministic error messages.
        Map<String, String> failedResults = new LinkedHashMap<>();

        try {
            for (String policy : policies) {
                String trimmed = policy.trim();
                if (isBlank(trimmed)) {
                    continue;
                }
                String failedFields = evaluator.evaluate(trimmed, deviceData,
                        context.getTenantDomain());
                if (failedFields == null) {
                    // At least one policy passed — device is compliant.
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Device passed policy: " + trimmed);
                    }
                    return null;
                }
                failedResults.put(trimmed, failedFields);
            }

            // All evaluated policies failed.
            if (failedResults.isEmpty()) {
                // policyNames was blank or all entries were whitespace — treat as no policy.
                return null;
            }

            String description = failedResults.entrySet().stream()
                    .map(e -> e.getKey() + ": [" + e.getValue() + "]")
                    .collect(Collectors.joining(", "));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Device failed all policies. " + description);
            }
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_USER_ERROR);
            response.setErrorCode(ErrorMessage.ERROR_DEVICE_POLICY_NOT_COMPLIANT.getCode());
            response.setErrorMessage(ErrorMessage.ERROR_DEVICE_POLICY_NOT_COMPLIANT.getMessage());
            response.setErrorDescription(String.format(
                    ErrorMessage.ERROR_DEVICE_POLICY_NOT_COMPLIANT.getDescription(),
                    policyNames, description));
            return response;

        } catch (PolicyManagementException | RuleEvaluationException e) {
            LOG.error("Policy evaluation failed for policies: " + policyNames, e);
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorCode(ErrorMessage.ERROR_WHILE_EVALUATING_POLICY.getCode());
            response.setErrorMessage(ErrorMessage.ERROR_WHILE_EVALUATING_POLICY.getMessage());
            response.setErrorDescription(String.format(
                    ErrorMessage.ERROR_WHILE_EVALUATING_POLICY.getDescription(), policyNames));
            return response;
        }
    }
}
