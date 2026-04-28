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

package org.wso2.carbon.identity.device.policy.management.internal.rule;

import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.config.DeviceFieldConfig;
import org.wso2.carbon.identity.device.policy.management.internal.config.DeviceFieldConfigLoader;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationResult;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

/**
 * Evaluates device policy compliance by reading device attributes from HTTP request headers
 * and running them through the rule evaluation engine.
 * Field-to-header mapping is driven by device-fields.json via DeviceFieldConfigLoader.
 */
public class DevicePolicyEvaluator {

    /**
     * Evaluates device policy compliance for the given policy and request.
     *
     * @return null if compliant, or a comma-separated string of failed field names if not compliant.
     */
    public String evaluate(String policyName, HttpServletRequest request, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException {

        Policy policy = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getPolicyManagementService()
                .getPolicyByName(policyName, tenantDomain);

        Map<String, Object> deviceData = new HashMap<>();
        for (DeviceFieldConfig field : DeviceFieldConfigLoader.getInstance().getFields()) {
            String value = request.getHeader(field.getHeader());
            deviceData.put(field.getName(), value != null ? value : "not_available");
        }

        FlowContext flowContext = new FlowContext(FlowType.DEVICE_POLICY, deviceData);
        RuleEvaluationResult result = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getRuleEvaluationService()
                .evaluate(policy.getRuleId(), flowContext, tenantDomain);

        if (result.isRuleSatisfied()) {
            return null;
        }
        return String.join(", ", result.getFailedFields());
    }
}
