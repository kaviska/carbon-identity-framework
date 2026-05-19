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

package org.wso2.carbon.identity.device.policy.management.internal.action;

import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;

import java.util.Map;

/**
 * Builds the action execution request for the DEVICE_POLICY action type.
 * Extracts device data from the flow context and populates it as request parameters
 * sent to the configured MDM endpoint.
 */
public class DevicePolicyActionRequestBuilder implements ActionExecutionRequestBuilder {

    private static final String DEVICE_DATA_KEY = "deviceData";
    private static final String TENANT_DOMAIN_KEY = "tenantDomain";

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.DEVICE_POLICY;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(FlowContext flowContext,
                                                             ActionExecutionRequestContext actionExecutionContext)
            throws ActionExecutionRequestBuilderException {

        @SuppressWarnings("unchecked")
        Map<String, Object> deviceData = flowContext.getValue(DEVICE_DATA_KEY, Map.class);
        if (deviceData == null) {
            throw new ActionExecutionRequestBuilderException(
                    "Device data is missing from flow context for DEVICE_POLICY action.");
        }

        String tenantDomain = flowContext.getValue(TENANT_DOMAIN_KEY, String.class);

        DevicePolicyEvent event = new DevicePolicyEvent(deviceData, tenantDomain);

        return new ActionExecutionRequest.Builder()
                .actionType(ActionType.DEVICE_POLICY)
                .event(event)
                .build();
    }
}
