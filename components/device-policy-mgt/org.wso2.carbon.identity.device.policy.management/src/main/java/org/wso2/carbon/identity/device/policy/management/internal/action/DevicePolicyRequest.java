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

import org.wso2.carbon.identity.action.execution.api.model.Param;
import org.wso2.carbon.identity.action.execution.api.model.Request;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * HTTP request model for the device policy compliance action.
 * Carries device attributes (platform, osVersion, etc.) as additional params sent to the MDM endpoint.
 */
public class DevicePolicyRequest extends Request {

    public DevicePolicyRequest(Map<String, Object> deviceData) {

        List<Param> params = new ArrayList<>();
        for (Map.Entry<String, Object> entry : deviceData.entrySet()) {
            if (entry.getValue() != null) {
                params.add(new Param(entry.getKey(), new String[]{String.valueOf(entry.getValue())}));
            }
        }
        this.additionalParams = params;
    }
}
