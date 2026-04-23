/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.device.policy.management.internal.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.policy.management.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementClientException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.dao.PolicyManagementDAO;
import org.wso2.carbon.identity.rule.management.api.exception.RuleManagementClientException;
import org.wso2.carbon.identity.rule.management.api.exception.RuleManagementException;
import org.wso2.carbon.identity.rule.management.api.model.ANDCombinedRule;
import org.wso2.carbon.identity.rule.management.api.model.Expression;
import org.wso2.carbon.identity.rule.management.api.model.FlowType;
import org.wso2.carbon.identity.rule.management.api.model.ORCombinedRule;
import org.wso2.carbon.identity.rule.management.api.model.Rule;
import org.wso2.carbon.identity.rule.management.api.service.RuleManagementService;
import org.wso2.carbon.identity.rule.management.api.util.RuleBuilder;

/**
 * Facade for Policy Management DAO.
 * Coordinates policy persistence and rule management as a single operation.
 */
public class PolicyManagementDAOFacade implements PolicyManagementDAO {

    private static final Log LOG = LogFactory.getLog(PolicyManagementDAOFacade.class);

    private final PolicyManagementDAO policyManagementDAO;

    public PolicyManagementDAOFacade(PolicyManagementDAO policyManagementDAO) {

        this.policyManagementDAO = policyManagementDAO;
    }

    @Override
    public Policy addPolicy(Policy policy, int tenantId) throws PolicyManagementException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        RuleManagementService ruleManagementService = DevicePolicyMgtComponentServiceHolder
                .getInstance().getRuleManagementService();
        try {
            validateRule(policy.getRule(), tenantDomain);
            Rule rule = ruleManagementService.addRule(policy.getRule(), tenantDomain);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Rule added successfully with ID: " + rule.getId() +
                        " for policy: " + policy.getName());
            }
            Policy policyWithRuleId = new Policy(
                    policy.getId(),
                    policy.getName(),
                    rule.getId(),
                    tenantDomain,
                    null);
            return policyManagementDAO.addPolicy(policyWithRuleId, tenantId);
        } catch (RuleManagementException e) {
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getMessage(),
                    String.format(ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getDescription(),
                            policy.getName()),
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getCode(), e);
        }
    }

    @Override
    public Policy updatePolicy(Policy policy, int tenantId) throws PolicyManagementException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        RuleManagementService ruleManagementService = DevicePolicyMgtComponentServiceHolder
                .getInstance().getRuleManagementService();

        // Fetch the existing policy to get the persisted ruleId so updateRule can find it.
        Policy existingPolicy = policyManagementDAO.getPolicyById(policy.getId(), tenantId);

        // Rebuild the rule with the existing rule UUID — the rule engine requires this to locate the record.
        ORCombinedRule ruleWithExistingId = new ORCombinedRule.Builder(
                (ORCombinedRule) policy.getRule())
                .setId(existingPolicy.getRuleId())
                .build();

        try {
            validateRule(policy.getRule(), tenantDomain);
            ruleManagementService.updateRule(ruleWithExistingId, tenantDomain);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Rule updated successfully for policy: " + policy.getId());
            }
            Policy policyWithRuleId = new Policy(
                    policy.getId(),
                    policy.getName(),
                    existingPolicy.getRuleId(),
                    tenantDomain,
                    null);
            return policyManagementDAO.updatePolicy(policyWithRuleId, tenantId);
        } catch (RuleManagementException e) {
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_UPDATING_RULE_FOR_POLICY.getMessage(),
                    String.format(ErrorMessage.ERROR_WHILE_UPDATING_RULE_FOR_POLICY.getDescription(),
                            policy.getId()),
                    ErrorMessage.ERROR_WHILE_UPDATING_RULE_FOR_POLICY.getCode(), e);
        }
    }

    @Override
    public void deletePolicy(String policyId, int tenantId) throws PolicyManagementException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        RuleManagementService ruleManagementService = DevicePolicyMgtComponentServiceHolder
                .getInstance().getRuleManagementService();
        Policy policy = policyManagementDAO.getPolicyById(policyId, tenantId);
        try {
            // Delete rule first: if policy delete later fails the user can retry;
            // the opposite order leaves an orphaned rule invisible to the user.
            ruleManagementService.deleteRule(policy.getRuleId(), tenantDomain);
            policyManagementDAO.deletePolicy(policyId, tenantId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Rule deleted successfully for policy: " + policyId);
            }
        } catch (RuleManagementException e) {
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_DELETING_RULE_FOR_POLICY.getMessage(),
                    String.format(ErrorMessage.ERROR_WHILE_DELETING_RULE_FOR_POLICY.getDescription(),
                            policyId),
                    ErrorMessage.ERROR_WHILE_DELETING_RULE_FOR_POLICY.getCode(), e);
        }
    }

    @Override
    public Policy getPolicyById(String policyId, int tenantId) throws PolicyManagementException {

        return policyManagementDAO.getPolicyById(policyId, tenantId);
    }

    @Override
    public Policy getPolicyByName(String policyName, int tenantId) throws PolicyManagementException {

        return policyManagementDAO.getPolicyByName(policyName, tenantId);
    }

    private void validateRule(Rule rule, String tenantDomain) throws PolicyManagementException {

        try {
            RuleBuilder ruleBuilder = RuleBuilder.create(FlowType.DEVICE_POLICY, tenantDomain);
            ORCombinedRule orRule = (ORCombinedRule) rule;
            boolean firstBranch = true;
            for (ANDCombinedRule andRule : orRule.getRules()) {
                if (!firstBranch) {
                    ruleBuilder.addOrCondition();
                }
                firstBranch = false;
                for (Expression expression : andRule.getExpressions()) {
                    ruleBuilder.addAndExpression(expression);
                }
            }
            ruleBuilder.build();
        } catch (RuleManagementClientException e) {
            throw new PolicyManagementClientException(
                    ErrorMessage.ERROR_INVALID_POLICY_RULE.getMessage(),
                    String.format(ErrorMessage.ERROR_INVALID_POLICY_RULE.getDescription(), e.getMessage()),
                    ErrorMessage.ERROR_INVALID_POLICY_RULE.getCode(), e);
        } catch (RuleManagementException e) {
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getMessage(),
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getDescription(),
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getCode(), e);
        }
    }
}
