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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.device.mgt.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtClientException;
import org.wso2.carbon.identity.device.mgt.api.exception.DeviceMgtException;
import org.wso2.carbon.identity.device.mgt.api.model.DeviceRegistrationInitiation;
import org.wso2.carbon.identity.device.mgt.api.model.RegisteredDevice;
import org.wso2.carbon.identity.device.mgt.api.service.DeviceManagementService;
import org.wso2.carbon.identity.device.policy.api.service.DevicePolicyEvaluator;
import org.wso2.carbon.identity.device.registration.executor.internal.DeviceRegistrationExecutorDataHolder;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_CLIENT_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

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

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REFERENCE =
            new TypeReference<Map<String, Object>>() { };

    private static final String CTX_REGISTRATION_ID = "device.registration.id";

    private static final String PROP_REGISTRATION_ID = "registrationId";
    private static final String PROP_CHALLENGE = "challenge";

    private static final String FIELD_PUBLIC_KEY = "publicKey";
    private static final String FIELD_SIGNATURE = "signature";
    private static final String FIELD_DEVICE_MODEL = "deviceModel";
    private static final String FIELD_METADATA = "metadata";
    private static final String FIELD_DEVICE_DATA = "deviceData";

    private static final String META_POLICY_NAME = "policyName";

    // Written to context after persistDevice() so rollback() can delete the record if a later executor fails.
    private static final String CTX_PERSISTED_DEVICE_ID = "device.persisted.id";

    @Override
    public String getName() {
        return DeviceRegistrationExecutorConstants.EXECUTOR_NAME;
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

        String persistedDeviceId = (String) context.getProperty(CTX_PERSISTED_DEVICE_ID);
        if (persistedDeviceId != null) {
            DeviceManagementService service =
                    DeviceRegistrationExecutorDataHolder.getInstance().getDeviceManagementService();
            try {
                service.deleteDevice(persistedDeviceId, context.getTenantDomain());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Rolled back persisted device: " + persistedDeviceId
                            + " for tenant: " + context.getTenantDomain());
                }
            } catch (DeviceMgtException e) {
                LOG.error("Failed to rollback persisted device: " + persistedDeviceId
                        + " in tenant: " + context.getTenantDomain(), e);
                ExecutorResponse response = new ExecutorResponse(STATUS_ERROR);
                response.setErrorCode(e.getErrorCode());
                response.setErrorMessage(e.getMessage());
                response.setErrorDescription(e.getDescription());
                return response;
            }
        }
        // Challenge cache entry expires automatically via TTL; nothing else to undo.
        return new ExecutorResponse(STATUS_COMPLETE);
    }

    @Override
    public List<String> getInitiationData() {
        return Collections.singletonList(USERNAME_CLAIM_URI);
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
                LOG.debug("Device registration initiated for user: " + LoggerUtils.getMaskedContent(username)
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

            if (FlowTypes.REGISTRATION.getType().equals(context.getFlowType())) {
                // userId is not yet assigned — UserProvisioningExecutor runs at END after this.
                // Defer the DB write to RegistrationFlowCompletionListener, which fires after
                // COMPLETE and has the real userId from FlowUser.
                ExecutorResponse response = new ExecutorResponse();
                response.setResult(STATUS_COMPLETE);
                Map<String, Object> ctxProps = new HashMap<>();
                ctxProps.put(DeviceRegistrationExecutorConstants.CTX_DEVICE_REGISTRATION, verified);
                response.setContextProperty(ctxProps);
                return response;
            }

            // Non-registration flow: userId already exists, persist immediately.
            service.persistDevice(verified, context.getTenantDomain());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Device registration completed for registrationId: " + registrationId);
            }
            // Record the device ID so rollback() can delete it if a subsequent executor fails.
            ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
            Map<String, Object> ctxProps = new HashMap<>();
            ctxProps.put(CTX_PERSISTED_DEVICE_ID, verified.getId());
            response.setContextProperty(ctxProps);
            return response;

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
            deviceData.putAll(OBJECT_MAPPER.readValue(json, MAP_TYPE_REFERENCE));
        } catch (JsonProcessingException e) {
            LOG.error("Failed to parse deviceData JSON submitted by SDK.", e);
        }
        return deviceData;
    }

    /**
     * Evaluates device compliance against a single named policy using attributes submitted by the
     * SDK in Phase 2.
     *
     * @return null if the device is compliant, or an error ExecutorResponse describing the failed
     *         fields if the device does not comply.
     */
    private ExecutorResponse evaluatePolicy(String policyName, FlowExecutionContext context) {

        DeviceRegistrationExecutorDataHolder holder = DeviceRegistrationExecutorDataHolder.getInstance();
        DevicePolicyEvaluator evaluator = holder.getDevicePolicyEvaluator();
        Map<String, Object> deviceData = parseDeviceData(context.getUserInputData());
        // Fill any missing fields so the rule engine always sees a complete map.
        for (String fieldName : evaluator.getFieldNames()) {
            deviceData.putIfAbsent(fieldName, "not_available");
        }

        holder.getIntegrityDataEnricher().enrich(deviceData, context.getApplicationId(),
                context.getTenantDomain());

        try {
            String failedFields = evaluator.evaluate(policyName, deviceData, context.getTenantDomain());
            if (failedFields == null) {
                // Device is compliant.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Device passed policy: " + policyName);
                }
                return null;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Device failed policy: " + policyName + " fields: [" + failedFields + "]");
            }
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_USER_ERROR);
            response.setErrorCode(ErrorMessage.ERROR_DEVICE_POLICY_NOT_COMPLIANT.getCode());
            response.setErrorMessage(ErrorMessage.ERROR_DEVICE_POLICY_NOT_COMPLIANT.getMessage());
            response.setErrorDescription(String.format(
                    ErrorMessage.ERROR_DEVICE_POLICY_NOT_COMPLIANT.getDescription(),
                    policyName, failedFields));
            return response;

        } catch (PolicyManagementException | RuleEvaluationException e) {
            LOG.error("Policy evaluation failed for policy: " + policyName, e);
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_ERROR);
            response.setErrorCode(ErrorMessage.ERROR_WHILE_EVALUATING_POLICY.getCode());
            response.setErrorMessage(ErrorMessage.ERROR_WHILE_EVALUATING_POLICY.getMessage());
            response.setErrorDescription(String.format(
                    ErrorMessage.ERROR_WHILE_EVALUATING_POLICY.getDescription(), policyName));
            return response;
        }
    }
}
