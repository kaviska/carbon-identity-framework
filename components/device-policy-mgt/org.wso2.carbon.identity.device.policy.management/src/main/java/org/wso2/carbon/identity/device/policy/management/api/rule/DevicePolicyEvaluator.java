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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.device.policy.management.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.api.model.PolicyAction;
import org.wso2.carbon.identity.device.policy.management.api.model.PolicyRule;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.config.DeviceFieldConfig;
import org.wso2.carbon.identity.device.policy.management.internal.config.DeviceFieldConfigLoader;
import org.wso2.carbon.identity.device.policy.management.internal.config.OsVersionRegistry;
import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationException;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationResult;
import org.wso2.carbon.identity.rule.management.api.model.ANDCombinedRule;
import org.wso2.carbon.identity.rule.management.api.model.Expression;
import org.wso2.carbon.identity.rule.management.api.model.ORCombinedRule;
import org.wso2.carbon.identity.rule.management.api.model.Rule;
import org.wso2.carbon.identity.rule.management.api.model.Value;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Evaluates device policy compliance against a named policy using pre-extracted device attribute data.
 *
 * <p>Two-phase evaluation:
 * <ol>
 *   <li>Rule phase — finds the rule for the device's platform and evaluates it. If no rule is configured
 *       for the platform, this phase is skipped (policy does not restrict that platform).</li>
 *   <li>Action phase — executes all configured actions in ascending exec_order via the action executor
 *       service. A failed action means the device is not compliant.</li>
 * </ol>
 *
 * <p>Callers are responsible for extracting device attributes from their source and passing them
 * as a plain Map. Use {@link #getFieldNames()} to discover which field names the evaluator expects.
 */
public class DevicePolicyEvaluator {

    private static final Log LOG = LogFactory.getLog(DevicePolicyEvaluator.class);
    private static final String DEVICE_PLATFORM_FIELD = "platform";
    private static final String DEVICE_DATA_KEY = "deviceData";
    private static final String TENANT_DOMAIN_KEY = "tenantDomain";

    private static final Set<String> OS_VERSION_FIELDS = new HashSet<>(Arrays.asList(
            "androidOsVersion", "iosOsVersion", "macosOsVersion", "windowsOsVersion"));

    /**
     * Evaluates device policy compliance for the given policy and device data.
     *
     * @param policyName   Name of the policy to evaluate against.
     * @param deviceData   Map of device field names to their values.
     * @param tenantDomain Tenant domain for policy lookup and rule evaluation.
     * @return {@code null} if the device is compliant, or a failure reason string if not.
     * @throws PolicyManagementException If the policy cannot be retrieved or an action fails unexpectedly.
     * @throws RuleEvaluationException   If rule evaluation fails.
     */
    public String evaluate(String policyName, Map<String, Object> deviceData, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException {

        Policy policy = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getPolicyManagementService()
                .getPolicyByName(policyName, tenantDomain);

        if (policy == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Policy not found: " + policyName + " for tenant: " + tenantDomain);
            }
            return policyName + ":policy_not_found";
        }

        // Phase 1: Rule evaluation by device platform.
        String failedFields = evaluateRule(policy, deviceData, tenantDomain);
        if (failedFields != null) {
            return failedFields;
        }

        // Phase 2: Action execution in exec_order.
        return executeActions(policy, deviceData, tenantDomain);
    }

    /**
     * Finds the rule matching the device platform and evaluates it.
     *
     * @return {@code null} if compliant (or no rule for platform), or a comma-separated list of failed fields.
     */
    private String evaluateRule(Policy policy, Map<String, Object> deviceData, String tenantDomain)
            throws PolicyManagementException, RuleEvaluationException {

        String platform = (String) deviceData.get(DEVICE_PLATFORM_FIELD);
        if (platform == null || platform.isEmpty()) {
            return null;
        }

        PolicyRule matchingRule = policy.getRules().stream()
                .filter(r -> platform.equalsIgnoreCase(r.getPlatform()))
                .findFirst()
                .orElse(null);

        if (matchingRule == null || matchingRule.getRule() == null) {
            return null;
        }

        Rule resolvedRule = resolveSymbolicOsVersions(matchingRule.getRule());
        FlowContext flowContext = new FlowContext(FlowType.DEVICE_POLICY, deviceData);
        RuleEvaluationResult result = DevicePolicyMgtComponentServiceHolder.getInstance()
                .getRuleEvaluationService()
                .evaluate(resolvedRule, flowContext, tenantDomain);

        if (!result.isRuleSatisfied()) {
            return String.join(", ", result.getFailedFields());
        }
        return null;
    }

    /**
     * Executes all policy actions in ascending exec_order via the action executor service.
     *
     * @return {@code null} if all actions succeed, or a failure reason string if any action fails.
     */
    private String executeActions(Policy policy, Map<String, Object> deviceData, String tenantDomain)
            throws PolicyManagementException {

        List<PolicyAction> sortedActions = policy.getActions().stream()
                .sorted(Comparator.comparingInt(PolicyAction::getExecOrder))
                .collect(Collectors.toList());

        for (PolicyAction policyAction : sortedActions) {
            org.wso2.carbon.identity.action.execution.api.model.FlowContext actionFlowContext =
                    org.wso2.carbon.identity.action.execution.api.model.FlowContext.create()
                            .add(DEVICE_DATA_KEY, deviceData)
                            .add(TENANT_DOMAIN_KEY, tenantDomain);

            try {
                ActionExecutionStatus status = DevicePolicyMgtComponentServiceHolder.getInstance()
                        .getActionExecutorService()
                        .execute(ActionType.DEVICE_POLICY, policyAction.getActionId(),
                                actionFlowContext, tenantDomain);

                if (status.getStatus() != ActionExecutionStatus.Status.SUCCESS) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Action not compliant for policy: " + policy.getName()
                                + ", action: " + policyAction.getActionType()
                                + ", status: " + status.getStatus());
                    }
                    return policy.getName() + ":action_not_compliant:" + policyAction.getActionType();
                }
            } catch (ActionExecutionException e) {
                throw new PolicyManagementServerException(
                        ErrorMessage.ERROR_WHILE_EXECUTING_ACTION_FOR_POLICY.getMessage(),
                        String.format(ErrorMessage.ERROR_WHILE_EXECUTING_ACTION_FOR_POLICY.getDescription(),
                                policy.getName(), policyAction.getActionType()),
                        ErrorMessage.ERROR_WHILE_EXECUTING_ACTION_FOR_POLICY.getCode(), e);
            }
        }
        return null;
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
            String resolved = OsVersionRegistry.getInstance().resolveList(fieldValue);
            return new Expression.Builder()
                    .field(expression.getField())
                    .operator(expression.getOperator())
                    .value(new Value(Value.Type.LIST, resolved))
                    .build();
        }

        if (type == Value.Type.RAW) {
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
     * Callers use this to know which keys to populate in the {@code deviceData} map.
     *
     * @return Unmodifiable list of field names (e.g., "platform", "osVersion", "isRooted").
     */
    public List<String> getFieldNames() {

        return DeviceFieldConfigLoader.getInstance().getFields().stream()
                .map(DeviceFieldConfig::getName)
                .collect(Collectors.toList());
    }

}
