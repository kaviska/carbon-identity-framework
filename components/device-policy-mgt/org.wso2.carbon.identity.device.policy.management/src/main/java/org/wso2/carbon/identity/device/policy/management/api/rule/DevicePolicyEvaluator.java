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

package org.wso2.carbon.identity.device.policy.management.api.rule;

import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.config.DeviceFieldConfig;
import org.wso2.carbon.identity.device.policy.management.internal.config.DeviceFieldConfigLoader;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationResult;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Evaluates device policy compliance against a named policy using pre-extracted device attribute data.
 * This class is OSGi-exported and can be used by any bundle that needs policy evaluation
 * (e.g., adaptive auth JS functions, flow executors).
 *
 * <p>Callers are responsible for extracting device attributes from their source
 * (HTTP headers, flow userInputData, etc.) and passing them as a plain Map.
 * Use {@link #getFieldNames()} to discover which field names the evaluator expects.
 */
public class DevicePolicyEvaluator {

    /**
     * Evaluates device policy compliance for the given policy and device data.
     *
     * @param policyName   Name of the policy to evaluate against.
     * @param deviceData   Map of device field names to their values. Unknown keys are ignored.
     * @param tenantDomain Tenant domain for policy lookup and rule evaluation.
     * @return {@code null} if the device is compliant, or a comma-separated string of failed
     *         field names if not compliant.
     * @throws PolicyManagementException If the policy cannot be retrieved.
     * @throws RuleEvaluationException   If rule evaluation fails.
     */
    public String evaluate(String policyName, Map<String, Object> deviceData, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException {

        Policy policy = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getPolicyManagementService()
                .getPolicyByName(policyName, tenantDomain);

        FlowContext flowContext = new FlowContext(FlowType.DEVICE_POLICY, deviceData);
        RuleEvaluationResult result = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getRuleEvaluationService()
                .evaluate(policy.getRuleId(), flowContext, tenantDomain);

        if (result.isRuleSatisfied()) {
            return null;
        }
        return String.join(", ", result.getFailedFields());
    }

    /**
     * Returns the list of device field names the evaluator recognises.
     * Callers should use this to know which keys to populate in the {@code deviceData} map
     * passed to {@link #evaluate(String, Map, String)}.
     *
     * @return Unmodifiable list of field names (e.g., "platform", "osVersion", "isRooted").
     */
    public List<String> getFieldNames() {

        return DeviceFieldConfigLoader.getInstance().getFields().stream()
                .map(DeviceFieldConfig::getName)
                .collect(Collectors.toList());
    }
}
