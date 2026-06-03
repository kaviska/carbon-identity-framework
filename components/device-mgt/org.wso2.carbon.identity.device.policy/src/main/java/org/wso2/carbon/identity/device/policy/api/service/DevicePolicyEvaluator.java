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

package org.wso2.carbon.identity.device.policy.api.service;

import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;

import java.util.List;
import java.util.Map;

/**
 * Evaluates device policy compliance against a named policy using pre-extracted device attribute data.
 * Finds the rule for the device's platform and evaluates it. If no rule is configured for the platform,
 * the policy does not restrict that platform and the device is treated as compliant.
 */
public interface DevicePolicyEvaluator {

    /**
     * Evaluates device policy compliance for the given policy and device data.
     *
     * @param policyName   Name of the policy to evaluate against.
     * @param deviceData   Map of device field names to their values.
     * @param tenantDomain Tenant domain for policy lookup and rule evaluation.
     * @return {@code null} if the device is compliant, or a failure reason string if not.
     * @throws PolicyManagementException If the policy cannot be retrieved.
     * @throws RuleEvaluationException   If rule evaluation fails.
     */
    String evaluate(String policyName, Map<String, Object> deviceData, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException;

    /**
     * Returns the list of device field names the evaluator recognises.
     * Callers use this to know which keys to populate in the {@code deviceData} map.
     *
     * @return Unmodifiable list of field names (e.g., "platform", "osVersion", "isRooted").
     */
    List<String> getFieldNames();
}
