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
import org.wso2.carbon.identity.device.registration.executor.internal.DeviceRegistrationExecutorDataHolder;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

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

/**
 * Flow executor for generic device registration.
 *
 * Implements a two-phase challenge-response protocol:
 *   Phase 1 — first call, no registrationId in context:
 *     Generates challenge via DeviceManagementService.initiateDeviceRegistration(), stores
 *     registrationId in FlowExecutionContext.properties, returns STATUS_USER_INPUT_REQUIRED
 *     so the SDK can render a "Registering device..." screen and sign the challenge.
 *
 *   Phase 2 — second call, registrationId present in context:
 *     Reads publicKey + signature + device metadata from userInputData, calls
 *     DeviceManagementService.completeDeviceRegistration() which verifies the ECDSA signature
 *     and persists the device, then returns STATUS_COMPLETE.
 */
public class DeviceRegistrationExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(DeviceRegistrationExecutor.class);

    public static final String EXECUTOR_NAME = "DeviceRegistrationExecutor";

    // FlowExecutionContext property keys.
    private static final String CTX_REGISTRATION_ID = "device.registration.id";

    // Holds the verified-but-not-yet-persisted RegisteredDevice in REGISTRATION flows.
    // RegistrationFlowCompletionListener reads this after UserProvisioningExecutor has run.
    public static final String CTX_DEVICE_REGISTRATION = "device.registration.data";

    // Keys sent in ExecutorResponse.additionalInfo to the SDK during Phase 1.
    private static final String PROP_REGISTRATION_ID = "registrationId";
    private static final String PROP_CHALLENGE = "challenge";

    // User input field names the SDK must submit in Phase 2.
    private static final String FIELD_PUBLIC_KEY   = "publicKey";
    private static final String FIELD_SIGNATURE    = "signature";
    private static final String FIELD_DEVICE_NAME  = "deviceName";
    private static final String FIELD_DEVICE_MODEL = "deviceModel";
    private static final String FIELD_METADATA     = "metadata";

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

            ExecutorResponse response = new ExecutorResponse();
            response.setResult(STATUS_CLIENT_INPUT_REQUIRED);
            response.setRequiredData(Arrays.asList(
                    FIELD_PUBLIC_KEY, FIELD_SIGNATURE, FIELD_DEVICE_NAME));
            response.setOptionalData(Arrays.asList(
                    FIELD_DEVICE_MODEL, FIELD_METADATA));
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

            if ("REGISTRATION".equals(context.getFlowType())) {
                // userId is not yet assigned — UserProvisioningExecutor runs at END after this.
                // Verify the signature now but defer the DB write to RegistrationFlowCompletionListener,
                // which fires after COMPLETE and has the real userId from FlowUser.
                RegisteredDevice pending = service.verifyDeviceRegistration(
                        registrationId,
                        input.get(FIELD_PUBLIC_KEY),
                        input.get(FIELD_SIGNATURE),
                        input.get(FIELD_DEVICE_NAME),
                        input.get(FIELD_DEVICE_MODEL),
                        input.get(FIELD_METADATA),
                        context.getTenantDomain());

                ExecutorResponse response = new ExecutorResponse();
                response.setResult(STATUS_COMPLETE);
                Map<String, Object> ctxProps = new HashMap<>();
                ctxProps.put(CTX_DEVICE_REGISTRATION, pending);
                response.setContextProperty(ctxProps);
                return response;
            }

            // Non-registration flow: userId already exists, write immediately.
            service.completeDeviceRegistration(
                    registrationId,
                    input.get(FIELD_PUBLIC_KEY),
                    input.get(FIELD_SIGNATURE),
                    input.get(FIELD_DEVICE_NAME),
                    input.get(FIELD_DEVICE_MODEL),
                    input.get(FIELD_METADATA),
                    context.getTenantDomain());

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
}
