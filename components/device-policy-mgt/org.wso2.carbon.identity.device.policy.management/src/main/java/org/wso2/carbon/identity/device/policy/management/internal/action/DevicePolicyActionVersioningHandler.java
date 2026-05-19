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

import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.service.ActionVersioningHandler;
import org.wso2.carbon.identity.action.management.api.model.Action;

/**
 * Versioning handler for the DEVICE_POLICY action type.
 * All versions are considered executable; no retirement policy is defined.
 */
public class DevicePolicyActionVersioningHandler implements ActionVersioningHandler {

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.DEVICE_POLICY;
    }

    @Override
    public boolean canExecute(ActionExecutionRequestContext actionExecutionRequestContext, FlowContext flowContext)
            throws ActionExecutionException {

        return true;
    }

    @Override
    public boolean isRetiredActionVersion(ActionType actionType, Action action)
            throws ActionExecutionException {

        return false;
    }
}
