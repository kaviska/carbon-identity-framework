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
import org.wso2.carbon.identity.device.policy.management.internal.config.OsVersionRegistry;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationResult;
import org.wso2.carbon.identity.rule.management.api.exception.RuleManagementException;
import org.wso2.carbon.identity.rule.management.api.model.ANDCombinedRule;
import org.wso2.carbon.identity.rule.management.api.model.Expression;
import org.wso2.carbon.identity.rule.management.api.model.ORCombinedRule;
import org.wso2.carbon.identity.rule.management.api.model.Rule;
import org.wso2.carbon.identity.rule.management.api.model.Value;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    private static final Set<String> OS_VERSION_FIELDS = new HashSet<>(Arrays.asList(
            "androidOsVersion", "iosOsVersion", "macosOsVersion", "windowsOsVersion"));

    /**
     * Evaluates device policy compliance for the given policy and device data.
     * Symbolic OS version references (e.g. LATEST_ANDROID) in LIST expressions are resolved
     * at evaluation time from os-versions.json before the rule engine sees them.
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

        Rule rule;
        try {
            rule = DevicePolicyMgtComponentServiceHolder.getInstance()
                    .getRuleManagementService()
                    .getRuleByRuleId(policy.getRuleId(), tenantDomain);
        } catch (RuleManagementException e) {
            throw new RuleEvaluationException("Error loading rule for policy: " + policyName, e);
        }

        Rule resolvedRule = resolveSymbolicOsVersions(rule);
        FlowContext flowContext = new FlowContext(FlowType.DEVICE_POLICY, deviceData);
        RuleEvaluationResult result = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getRuleEvaluationService()
                .evaluate(resolvedRule, flowContext, tenantDomain);

        if (result.isRuleSatisfied()) {
            return null;
        }
        return String.join(", ", result.getFailedFields());
    }

    /**
     * Walks the rule and resolves symbolic OS version names (e.g. LATEST_ANDROID) in LIST expressions
     * to actual version numbers from os-versions.json.
     */
    private Rule resolveSymbolicOsVersions(Rule rule) {

        ORCombinedRule orRule = (ORCombinedRule) rule;
        ORCombinedRule.Builder orBuilder = new ORCombinedRule.Builder()
                .setId(rule.getId())
                .setActive(rule.isActive());

        for (ANDCombinedRule andRule : orRule.getRules()) {
            ANDCombinedRule.Builder andBuilder = new ANDCombinedRule.Builder();
            for (Expression expression : andRule.getExpressions()) {
                andBuilder.addExpression(resolveExpression(expression));
            }
            orBuilder.addRule(andBuilder.build());
        }
        return orBuilder.build();
    }

    private Expression resolveExpression(Expression expression) {

        if (!OS_VERSION_FIELDS.contains(expression.getField())) {
            return expression;
        }

        Value.Type type = expression.getValue().getType();
        String fieldValue = expression.getValue().getFieldValue();

        if (type == Value.Type.LIST) {
            // in operator: resolve each comma-separated symbolic token.
            String resolved = OsVersionRegistry.getInstance().resolveList(fieldValue);
            return new Expression.Builder()
                    .field(expression.getField())
                    .operator(expression.getOperator())
                    .value(new Value(Value.Type.LIST, resolved))
                    .build();
        }

        if (type == Value.Type.RAW) {
            // equals / greaterThanOrEquals with a single symbolic token (e.g. LATEST_ANDROID).
            String resolved = OsVersionRegistry.getInstance().resolveToken(fieldValue);
            return new Expression.Builder()
                    .field(expression.getField())
                    .operator(expression.getOperator())
                    .value(new Value(Value.Type.NUMBER, resolved))
                    .build();
        }

        return expression;
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
