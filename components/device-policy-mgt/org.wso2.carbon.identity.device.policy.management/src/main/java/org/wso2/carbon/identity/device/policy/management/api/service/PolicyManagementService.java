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

package org.wso2.carbon.identity.device.policy.management.api.service;

import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementClientException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementServerException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.api.model.PolicyRule;

import java.util.List;

/**
 * Service interface for managing device compliance policies.
 *
 * <p>Defines CRUD operations for {@link Policy} entities. A policy is a tenant-scoped
 * entity uniquely identified by ID; the combination of policy name and tenant is also
 * unique. Each policy carries a set of platform-specific rules and an ordered list of
 * actions that run during compliance evaluation.
 *
 * <p>All mutating methods throw {@link PolicyManagementClientException} for
 * caller-correctable errors (invalid input, entity not found) and
 * {@link PolicyManagementServerException} for internal failures (database errors,
 * downstream service errors).
 */
public interface PolicyManagementService {

    /**
     * Creates a new policy under the given tenant.
     *
     * <p>The {@code policy.id} field is ignored; a server-generated UUID is assigned.
     * The policy name must be non-blank. Rule and action lists are persisted as
     * supplied. The returned {@link Policy} reflects the persisted state, including
     * the assigned ID.
     *
     * @param policy       Policy to create. Name must be non-blank; ID is ignored.
     * @param tenantDomain Tenant domain under which the policy is created.
     * @return The created policy with its server-assigned ID.
     * @throws PolicyManagementClientException If the policy name is missing or invalid.
     * @throws PolicyManagementException       If persistence fails for any other reason.
     */
    Policy addPolicy(Policy policy, String tenantDomain) throws PolicyManagementException;

    /**
     * Replaces an existing policy with the supplied state (PUT semantics).
     *
     * <p>The policy is identified by {@code policy.id}. All top-level fields, rules,
     * and actions are replaced wholesale — fields omitted from the supplied policy
     * are cleared, not preserved. Partial updates are not supported.
     *
     * @param policy       Policy with the new state. ID must reference an existing
     *                     policy; name must be non-blank.
     * @param tenantDomain Tenant domain of the policy.
     * @return The updated policy as persisted.
     * @throws PolicyManagementClientException If the policy name is invalid or no
     *                                         policy exists for the given ID under
     *                                         the tenant.
     * @throws PolicyManagementException       If persistence fails for any other reason.
     */
    Policy updatePolicy(Policy policy, String tenantDomain) throws PolicyManagementException;

    /**
     * Deletes the policy with the given ID under the tenant.
     *
     * <p>Performs a hard delete: the row is removed from the database, along with
     * cascade-deletion of associated rules and actions. The operation is idempotent —
     * deleting a non-existent policy is a silent no-op, not an error.
     *
     * @param policyId     ID of the policy to delete.
     * @param tenantDomain Tenant domain of the policy.
     * @throws PolicyManagementException If persistence fails.
     */
    void deletePolicy(String policyId, String tenantDomain) throws PolicyManagementException;

    /**
     * Retrieves a policy by its ID under the tenant.
     *
     * <p>The returned policy has its rule list <em>hydrated</em> — each
     * {@link PolicyRule} carries the full {@code Rule} object resolved from rule-mgt,
     * not just the rule ID.
     *
     * @param policyId     ID of the policy to retrieve.
     * @param tenantDomain Tenant domain of the policy.
     * @return The policy with hydrated rules, or {@code null} if no policy exists
     *         for the given ID under the tenant.
     * @throws PolicyManagementException If retrieval fails or rule hydration fails.
     */
    Policy getPolicyById(String policyId, String tenantDomain) throws PolicyManagementException;

    /**
     * Retrieves a policy by its name under the tenant.
     *
     * <p>Policy names are unique per tenant ({@code UNIQUE (POLICY_NAME, TENANT_ID)}),
     * so at most one match is possible. The returned policy has its rule list
     * <em>hydrated</em> — see {@link #getPolicyById}.
     *
     * @param policyName   Name of the policy to retrieve.
     * @param tenantDomain Tenant domain of the policy.
     * @return The policy with hydrated rules, or {@code null} if no policy exists
     *         with the given name under the tenant.
     * @throws PolicyManagementException If retrieval fails or rule hydration fails.
     */
    Policy getPolicyByName(String policyName, String tenantDomain) throws PolicyManagementException;

    /**
     * Retrieves all policies for the tenant.
     *
     * <p>Rules in the returned policies are <em>not hydrated</em>: each
     * {@link PolicyRule} carries only its rule ID and platform, with the {@code rule}
     * field left {@code null}. Call {@link #getPolicyById} on a specific policy to
     * obtain the fully hydrated form. This avoids fan-out lookups to rule-mgt when
     * listing.
     *
     * @param tenantDomain Tenant domain whose policies should be retrieved.
     * @return List of policies (possibly empty) for the tenant. Never {@code null}.
     * @throws PolicyManagementException If retrieval fails.
     */
    List<Policy> getPolicies(String tenantDomain) throws PolicyManagementException;
}
