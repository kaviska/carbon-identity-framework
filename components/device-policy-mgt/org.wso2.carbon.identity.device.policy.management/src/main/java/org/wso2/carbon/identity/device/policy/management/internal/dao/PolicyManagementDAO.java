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

package org.wso2.carbon.identity.device.policy.management.internal.dao;

import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;

import java.util.List;

/**
 * Interface for Policy Management DAO.
 * Handles CRUD for IDN_POLICY, IDN_POLICY_RULE, and IDN_POLICY_ACTION tables.
 * Returns Policy objects with PolicyRule/PolicyAction lists populated (ruleIds and actionIds only — no hydrated rules).
 */
public interface PolicyManagementDAO {

    Policy addPolicy(Policy policy, int tenantId) throws PolicyManagementException;

    Policy updatePolicy(Policy policy, int tenantId) throws PolicyManagementException;

    void deletePolicy(String policyId, int tenantId) throws PolicyManagementException;

    Policy getPolicyById(String policyId, int tenantId) throws PolicyManagementException;

    Policy getPolicyByName(String policyName, int tenantId) throws PolicyManagementException;

    List<Policy> getPolicies(int tenantId) throws PolicyManagementException;
}
