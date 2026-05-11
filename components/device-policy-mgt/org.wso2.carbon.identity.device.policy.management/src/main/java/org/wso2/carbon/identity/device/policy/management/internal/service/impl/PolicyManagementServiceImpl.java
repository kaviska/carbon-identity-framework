/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.api.service.PolicyManagementService;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.internal.component.DevicePolicyMgtComponentServiceHolder;
import org.wso2.carbon.identity.device.policy.management.internal.dao.PolicyManagementDAO;
import org.wso2.carbon.identity.device.policy.management.internal.dao.impl.PolicyManagementDAOFacade;
import org.wso2.carbon.identity.device.policy.management.internal.dao.impl.PolicyManagementDAOImpl;
import org.wso2.carbon.identity.rule.management.api.exception.RuleManagementException;
import org.wso2.carbon.identity.rule.management.api.model.Rule;

import java.util.List;
import java.util.UUID;

/**
 * Implementation of Policy Management Service.
 */
public class PolicyManagementServiceImpl implements PolicyManagementService {

    private static final Log LOG = LogFactory.getLog(PolicyManagementServiceImpl.class);
    private static final PolicyManagementServiceImpl policyManagementService =
            new PolicyManagementServiceImpl();
    private final PolicyManagementDAO policyManagementDAO;

    private PolicyManagementServiceImpl() {

        policyManagementDAO = new PolicyManagementDAOFacade(new PolicyManagementDAOImpl());
    }

    public static PolicyManagementServiceImpl getInstance() {

        return policyManagementService;
    }

    @Override
    public Policy addPolicy(Policy policy, String tenantDomain)
            throws PolicyManagementException {

        validatePolicyFields(policy);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        // generate UUID for new policy
        Policy policyWithId = new Policy(
                UUID.randomUUID().toString(),
                policy.getName(),
                policy.getRuleId(),
                tenantDomain,
                policy.getRule());

        Policy createdPolicy = policyManagementDAO.addPolicy(policyWithId, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Policy added successfully with ID: " + policyWithId.getId() +
                    " for tenant: " + tenantDomain);
        }
        return createdPolicy;
    }

    @Override
    public Policy updatePolicy(Policy policy, String tenantDomain)
            throws PolicyManagementException {

        validatePolicyFields(policy);
        validateIfPolicyExists(policy.getId(), tenantDomain);

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        Policy updatedPolicy = policyManagementDAO.updatePolicy(policy, tenantId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Policy updated successfully with ID: " + policy.getId() +
                    " for tenant: " + tenantDomain);
        }
        return updatedPolicy;
    }

    @Override
    public void deletePolicy(String policyId, String tenantDomain)
            throws PolicyManagementException {

        if (isPolicyExists(policyId, tenantDomain)) {
            policyManagementDAO.deletePolicy(
                    policyId,
                    IdentityTenantUtil.getTenantId(tenantDomain));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Policy deleted successfully with ID: " + policyId +
                        " for tenant: " + tenantDomain);
            }
        }
    }

    @Override
    public Policy getPolicyById(String policyId, String tenantDomain)
            throws PolicyManagementException {

        Policy policy = policyManagementDAO.getPolicyById(
                policyId, IdentityTenantUtil.getTenantId(tenantDomain));
        if (policy == null || policy.getRuleId() == null) {
            return policy;
        }
        try {
            Rule rule = DevicePolicyMgtComponentServiceHolder.getInstance()
                    .getRuleManagementService()
                    .getRuleByRuleId(policy.getRuleId(), tenantDomain);
            return new Policy(policy.getId(), policy.getName(), policy.getRuleId(),
                    policy.getTenantDomain(), rule);
        } catch (RuleManagementException e) {
            throw new PolicyManagementServerException(
                    ErrorMessage.ERROR_WHILE_RETRIEVING_POLICY.getMessage(),
                    ErrorMessage.ERROR_WHILE_RETRIEVING_POLICY.getDescription(),
                    ErrorMessage.ERROR_WHILE_RETRIEVING_POLICY.getCode(), e);
        }
    }

    @Override
    public Policy getPolicyByName(String policyName, String tenantDomain)
            throws PolicyManagementException {

        return policyManagementDAO.getPolicyByName(
                policyName,
                IdentityTenantUtil.getTenantId(tenantDomain));
    }

    @Override
    public List<Policy> getPolicies(String tenantDomain) throws PolicyManagementException {

        return policyManagementDAO.getPolicies(IdentityTenantUtil.getTenantId(tenantDomain));
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

    private boolean isPolicyExists(String policyId, String tenantDomain)
            throws PolicyManagementException {

        Policy existingPolicy = policyManagementDAO.getPolicyById(
                policyId,
                IdentityTenantUtil.getTenantId(tenantDomain));
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
