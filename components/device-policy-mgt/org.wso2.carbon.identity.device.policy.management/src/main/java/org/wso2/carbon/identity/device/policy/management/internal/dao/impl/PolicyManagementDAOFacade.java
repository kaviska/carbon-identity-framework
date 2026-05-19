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

package org.wso2.carbon.identity.device.policy.management.internal.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.policy.management.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementClientException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.api.model.PolicyRule;
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

import java.util.ArrayList;
import java.util.List;

/**
 * Facade for Policy Management DAO.
 * Coordinates between rule-mgt service and the policy DB layer as a single logical operation.
 * Implements best-effort saga compensation: if the DB write fails after rule-mgt succeeded,
 * we attempt to roll back rule-mgt changes.
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

        List<String> createdRuleIds = new ArrayList<>();
        List<PolicyRule> rulesWithIds = new ArrayList<>();

        try {
            for (PolicyRule pr : policy.getRules()) {
                validateRule(pr.getRule(), tenantDomain);
                Rule createdRule = ruleManagementService.addRule(pr.getRule(), tenantDomain);
                createdRuleIds.add(createdRule.getId());
                rulesWithIds.add(new PolicyRule(pr.getId(), createdRule.getId(), pr.getPlatform(), null));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Rule added for policy platform '" + pr.getPlatform()
                            + "' with ruleId: " + createdRule.getId());
                }
            }
        } catch (RuleManagementException e) {
            compensateCreatedRules(createdRuleIds, tenantDomain, ruleManagementService);
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getMessage(),
                    String.format(ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getDescription(), policy.getName()),
                    ErrorMessage.ERROR_WHILE_ADDING_RULE_FOR_POLICY.getCode(), e);
        }

        Policy policyWithRuleIds = new Policy(policy.getId(), policy.getName(), tenantDomain,
                rulesWithIds, policy.getActions());

        try {
            return policyManagementDAO.addPolicy(policyWithRuleIds, tenantId);
        } catch (PolicyManagementException e) {
            compensateCreatedRules(createdRuleIds, tenantDomain, ruleManagementService);
            throw e;
        }
    }

    @Override
    public Policy updatePolicy(Policy policy, int tenantId) throws PolicyManagementException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        RuleManagementService ruleManagementService = DevicePolicyMgtComponentServiceHolder
                .getInstance().getRuleManagementService();

        Policy existingPolicy = policyManagementDAO.getPolicyById(policy.getId(), tenantId);

        deleteRulesFromRuleManagementService(existingPolicy.getRules(), tenantDomain, ruleManagementService,
                policy.getId());

        List<String> createdRuleIds = new ArrayList<>();
        List<PolicyRule> rulesWithIds = new ArrayList<>();

        try {
            for (PolicyRule pr : policy.getRules()) {
                validateRule(pr.getRule(), tenantDomain);
                Rule createdRule = ruleManagementService.addRule(pr.getRule(), tenantDomain);
                createdRuleIds.add(createdRule.getId());
                rulesWithIds.add(new PolicyRule(pr.getId(), createdRule.getId(), pr.getPlatform(), null));
            }
        } catch (RuleManagementException e) {
            compensateCreatedRules(createdRuleIds, tenantDomain, ruleManagementService);
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_UPDATING_RULE_FOR_POLICY.getMessage(),
                    String.format(ErrorMessage.ERROR_WHILE_UPDATING_RULE_FOR_POLICY.getDescription(),
                            policy.getId()),
                    ErrorMessage.ERROR_WHILE_UPDATING_RULE_FOR_POLICY.getCode(), e);
        }

        Policy policyWithRuleIds = new Policy(policy.getId(), policy.getName(), tenantDomain,
                rulesWithIds, policy.getActions());

        try {
            return policyManagementDAO.updatePolicy(policyWithRuleIds, tenantId);
        } catch (PolicyManagementException e) {
            compensateCreatedRules(createdRuleIds, tenantDomain, ruleManagementService);
            throw e;
        }
    }

    @Override
    public void deletePolicy(String policyId, int tenantId) throws PolicyManagementException {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        RuleManagementService ruleManagementService = DevicePolicyMgtComponentServiceHolder
                .getInstance().getRuleManagementService();

        Policy existingPolicy = policyManagementDAO.getPolicyById(policyId, tenantId);

        policyManagementDAO.deletePolicy(policyId, tenantId);

        if (existingPolicy != null) {
            deleteRulesFromRuleManagementService(existingPolicy.getRules(), tenantDomain, ruleManagementService,
                    policyId);
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

    @Override
    public List<Policy> getPolicies(int tenantId) throws PolicyManagementException {

        return policyManagementDAO.getPolicies(tenantId);
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

    private void deleteRulesFromRuleManagementService(List<PolicyRule> rules, String tenantDomain,
                                                      RuleManagementService ruleManagementService,
                                                      String policyId) throws PolicyManagementException {

        for (PolicyRule pr : rules) {
            try {
                ruleManagementService.deleteRule(pr.getRuleId(), tenantDomain);
            } catch (RuleManagementException e) {
                throw new PolicyManagementServerException(
                        ErrorMessage.ERROR_WHILE_DELETING_RULE_FOR_POLICY.getMessage(),
                        String.format(ErrorMessage.ERROR_WHILE_DELETING_RULE_FOR_POLICY.getDescription(), policyId),
                        ErrorMessage.ERROR_WHILE_DELETING_RULE_FOR_POLICY.getCode(), e);
            }
        }
    }

    private void compensateCreatedRules(List<String> ruleIds, String tenantDomain,
                                        RuleManagementService ruleManagementService) {

        for (String ruleId : ruleIds) {
            try {
                ruleManagementService.deleteRule(ruleId, tenantDomain);
            } catch (RuleManagementException ex) {
                LOG.error("Saga compensation failed: could not delete rule " + ruleId
                        + " from rule-mgt after policy persistence failure.", ex);
            }
        }
    }
}
