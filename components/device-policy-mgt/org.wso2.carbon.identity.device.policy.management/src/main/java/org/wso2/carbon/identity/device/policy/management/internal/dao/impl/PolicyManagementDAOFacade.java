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
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.dao.PolicyManagementDAO;
import org.wso2.carbon.identity.rule.management.api.exception.RuleManagementException;
import org.wso2.carbon.identity.rule.management.api.model.Rule;
import org.wso2.carbon.identity.rule.management.api.service.RuleManagementService;

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
        try {
            ruleManagementService.updateRule(policy.getRule(), tenantDomain);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Rule updated successfully for policy: " + policy.getId());
            }
            return policyManagementDAO.updatePolicy(policy, tenantId);
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
            policyManagementDAO.deletePolicy(policyId, tenantId);
            ruleManagementService.deleteRule(policy.getRuleId(), tenantDomain);
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
}
