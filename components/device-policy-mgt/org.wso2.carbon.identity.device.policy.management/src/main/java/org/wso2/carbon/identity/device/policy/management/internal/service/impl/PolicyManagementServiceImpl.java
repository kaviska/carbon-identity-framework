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

package org.wso2.carbon.identity.device.policy.management.internal.service.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.policy.management.api.constant.ErrorMessage;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementClientException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.api.model.PolicyRule;
import org.wso2.carbon.identity.device.policy.management.api.service.PolicyManagementService;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.dao.PolicyManagementDAO;
import org.wso2.carbon.identity.device.policy.management.internal.dao.impl.PolicyManagementDAOFacade;
import org.wso2.carbon.identity.device.policy.management.internal.dao.impl.PolicyManagementDAOImpl;
import org.wso2.carbon.identity.rule.management.api.exception.RuleManagementException;
import org.wso2.carbon.identity.rule.management.api.model.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Implementation of Policy Management Service.
 * Orchestrates between the DAO layer (DB) and rule hydration via rule-mgt service.
 */
public class PolicyManagementServiceImpl implements PolicyManagementService {

    private static final Log LOG = LogFactory.getLog(PolicyManagementServiceImpl.class);
    private static final PolicyManagementServiceImpl INSTANCE = new PolicyManagementServiceImpl();
    private final PolicyManagementDAO policyManagementDAO;

    private PolicyManagementServiceImpl() {

        policyManagementDAO = new PolicyManagementDAOFacade(new PolicyManagementDAOImpl());
    }

    public static PolicyManagementServiceImpl getInstance() {

        return INSTANCE;
    }

    @Override
    public Policy addPolicy(Policy policy, String tenantDomain) throws PolicyManagementException {

        validatePolicyFields(policy);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        Policy policyWithId = new Policy(
                UUID.randomUUID().toString(),
                policy.getName(),
                tenantDomain,
                policy.getRules(),
                policy.getActions());

        Policy created = policyManagementDAO.addPolicy(policyWithId, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Policy added with ID: " + created.getId() + " for tenant: " + tenantDomain);
        }
        return created;
    }

    @Override
    public Policy updatePolicy(Policy policy, String tenantDomain) throws PolicyManagementException {

        validatePolicyFields(policy);
        validateIfPolicyExists(policy.getId(), tenantDomain);

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        Policy updated = policyManagementDAO.updatePolicy(policy, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Policy updated with ID: " + policy.getId() + " for tenant: " + tenantDomain);
        }
        return updated;
    }

    @Override
    public void deletePolicy(String policyId, String tenantDomain) throws PolicyManagementException {

        if (isPolicyExists(policyId, tenantDomain)) {
            policyManagementDAO.deletePolicy(policyId, IdentityTenantUtil.getTenantId(tenantDomain));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Policy deleted with ID: " + policyId + " for tenant: " + tenantDomain);
            }
        }
    }

    @Override
    public Policy getPolicyById(String policyId, String tenantDomain) throws PolicyManagementException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        Policy policy = policyManagementDAO.getPolicyById(policyId, tenantId);
        if (policy == null) {
            return null;
        }
        return hydrateRules(policy, tenantDomain);
    }

    @Override
    public Policy getPolicyByName(String policyName, String tenantDomain) throws PolicyManagementException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        Policy policy = policyManagementDAO.getPolicyByName(policyName, tenantId);
        if (policy == null) {
            return null;
        }
        return hydrateRules(policy, tenantDomain);
    }

    @Override
    public List<Policy> getPolicies(String tenantDomain) throws PolicyManagementException {

        return policyManagementDAO.getPolicies(IdentityTenantUtil.getTenantId(tenantDomain));
    }

    /**
     * Hydrates the PolicyRule list within a Policy by fetching full Rule objects from rule-mgt.
     * PolicyAction list is returned as-is (no hydration needed — actionIds are sufficient for execution).
     */
    private Policy hydrateRules(Policy policy, String tenantDomain) throws PolicyManagementException {

        List<PolicyRule> hydratedRules = new ArrayList<>();
        for (PolicyRule pr : policy.getRules()) {
            try {
                Rule rule = DevicePolicyMgtComponentServiceHolder.getInstance()
                        .getRuleManagementService()
                        .getRuleByRuleId(pr.getRuleId(), tenantDomain);
                hydratedRules.add(new PolicyRule(pr.getId(), pr.getRuleId(), pr.getPlatform(), rule));
            } catch (RuleManagementException e) {
                throw new PolicyManagementServerException(
                        ErrorMessage.ERROR_WHILE_RETRIEVING_POLICY.getMessage(),
                        ErrorMessage.ERROR_WHILE_RETRIEVING_POLICY.getDescription(),
                        ErrorMessage.ERROR_WHILE_RETRIEVING_POLICY.getCode(), e);
            }
        }
        return new Policy(policy.getId(), policy.getName(), policy.getTenantDomain(),
                hydratedRules, policy.getActions());
    }

    private void validateIfPolicyExists(String policyId, String tenantDomain)
            throws PolicyManagementException {

        if (!isPolicyExists(policyId, tenantDomain)) {
            throw new PolicyManagementClientException(
                    ErrorMessage.ERROR_POLICY_NOT_FOUND.getMessage(),
                    String.format(ErrorMessage.ERROR_POLICY_NOT_FOUND.getDescription(), policyId),
                    ErrorMessage.ERROR_POLICY_NOT_FOUND.getCode());
        }
    }

    private boolean isPolicyExists(String policyId, String tenantDomain) throws PolicyManagementException {

        Policy existingPolicy = policyManagementDAO.getPolicyById(
                policyId, IdentityTenantUtil.getTenantId(tenantDomain));
        return existingPolicy != null;
    }

    private void validatePolicyFields(Policy policy) throws PolicyManagementClientException {

        if (policy.getName() == null || policy.getName().trim().isEmpty()) {
            throw new PolicyManagementClientException(
                    ErrorMessage.ERROR_INVALID_POLICY_REQUEST_FIELD.getMessage(),
                    String.format(ErrorMessage.ERROR_INVALID_POLICY_REQUEST_FIELD.getDescription(),
                            "Policy name"),
                    ErrorMessage.ERROR_INVALID_POLICY_REQUEST_FIELD.getCode());
        }
    }
}
