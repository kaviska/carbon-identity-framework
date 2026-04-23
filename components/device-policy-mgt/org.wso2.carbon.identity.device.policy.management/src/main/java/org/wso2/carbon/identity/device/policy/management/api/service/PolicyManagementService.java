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

package org.wso2.carbon.identity.device.policy.management.api.service;

import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;

/**
 * Interface for Policy Management Service.
 */
public interface PolicyManagementService {

    Policy addPolicy(Policy policy, String tenantDomain) throws PolicyManagementException;

    Policy updatePolicy(Policy policy, String tenantDomain) throws PolicyManagementException;

    void deletePolicy(String policyId, String tenantDomain) throws PolicyManagementException;

    Policy getPolicyById(String policyId, String tenantDomain) throws PolicyManagementException;

    Policy getPolicyByName(String policyName, String tenantDomain) throws PolicyManagementException;
}
