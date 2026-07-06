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

package org.wso2.carbon.identity.device.policy.internal.service.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.device.policy.api.service.DevicePolicyEvaluator;
import org.wso2.carbon.identity.device.policy.internal.component.DevicePolicyComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.internal.config.DeviceFieldConfig;
import org.wso2.carbon.identity.device.policy.internal.config.DeviceFieldConfigLoader;
import org.wso2.carbon.identity.policy.evaluation.api.exception.PolicyEvaluationException;
import org.wso2.carbon.identity.policy.evaluation.api.model.PolicyEvaluationResult;
import org.wso2.carbon.identity.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.policy.management.api.model.Policy;
import org.wso2.carbon.identity.policy.management.api.model.PolicyResource;
import org.wso2.carbon.identity.policy.management.api.model.ResourceType;
import org.wso2.carbon.identity.policy.management.api.model.RulePolicyResource;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.management.api.model.Expression;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link DevicePolicyEvaluator}.
 */
public class DevicePolicyEvaluatorImpl implements DevicePolicyEvaluator {

    private static final Log LOG = LogFactory.getLog(DevicePolicyEvaluatorImpl.class);
    private static final String DEVICE_PLATFORM_FIELD = "platform";

    @Override
    public String evaluate(String policyName, Map<String, Object> deviceData, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException, PolicyEvaluationException {

        String platform = (String) deviceData.get(DEVICE_PLATFORM_FIELD);

        String missingFields = findMissingRequiredFields(policyName, platform, deviceData, tenantDomain);
        if (missingFields != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Device data incomplete for policy '" + policyName + "': [" + missingFields + "]");
            }
            return missingFields;
        }

        FlowContext flowContext = new FlowContext(FlowType.DEVICE_POLICY, deviceData);
        PolicyEvaluationResult result = DevicePolicyComponentServiceHolder.getInstance()
                .getPolicyEvaluationService()
                .evaluate(policyName, platform != null ? platform : "", flowContext, tenantDomain);

        if (result == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Policy not found: " + policyName + " for tenant: " + tenantDomain);
            }
            return policyName + ":policy_not_found";
        }

        if (!result.isSatisfied()) {
            List<String> failedFields = result.getOutcomes().stream()
                    .filter(outcome -> !outcome.isSatisfied())
                    .flatMap(outcome -> outcome.getFailedFields().stream())
                    .collect(Collectors.toList());
            return String.join(", ", failedFields);
        }
        return null;
    }

    /**
     * Returns a comma-separated list of fields the matching rule requires that the device did not
     * supply, or null when the device supplied everything the rule needs.
     *
     * @param policyName   Policy name.
     * @param platform     Device platform (rule selector).
     * @param deviceData   Submitted device attributes.
     * @param tenantDomain Tenant domain.
     * @return Missing field names joined by ", ", or null if complete.
     * @throws PolicyManagementException If the policy cannot be retrieved.
     */
    private String findMissingRequiredFields(String policyName, String platform,
            Map<String, Object> deviceData, String tenantDomain) throws PolicyManagementException {

        if (platform == null || platform.trim().isEmpty()) {
            return DEVICE_PLATFORM_FIELD;
        }
        Policy policy = DevicePolicyComponentServiceHolder.getInstance()
                .getPolicyManagementService()
                .getPolicyByName(policyName, tenantDomain);
        if (policy == null) {
            return null;
        }
        PolicyResource resource = policy.getResources().stream()
                .filter(r -> r.getResourceType() == ResourceType.RULE
                        && platform.equalsIgnoreCase(r.getTarget()))
                .findFirst()
                .orElse(null);
        if (!(resource instanceof RulePolicyResource)) {
            return null;
        }
        RulePolicyResource ruleResource = (RulePolicyResource) resource;
        if (ruleResource.getRule() == null) {
            return null;
        }
        List<String> missing = ruleResource.getRule().getExpressions().stream()
                .map(Expression::getField)
                .distinct()
                .filter(field -> {
                    Object value = deviceData.get(field);
                    return value == null || String.valueOf(value).trim().isEmpty();
                })
                .collect(Collectors.toList());
        return missing.isEmpty() ? null : String.join(", ", missing);
    }

    @Override
    public List<String> getFieldNames() {

        return DeviceFieldConfigLoader.getInstance().getFields().stream()
                .map(DeviceFieldConfig::getName)
                .collect(Collectors.toList());
    }
}
