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

package org.wso2.carbon.identity.device.policy.management.dao;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.policy.management.api.exception.PolicyManagementException;
import org.wso2.carbon.identity.device.policy.management.api.model.Policy;
import org.wso2.carbon.identity.device.policy.management.internal.dao.impl.PolicyManagementDAOImpl;

import java.util.UUID;

import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for PolicyManagementDAOImpl.
 */
@WithCarbonHome
@WithH2Database(files = {"dbscripts/h2.sql"})
public class PolicyManagementDAOImplTest {

    private static final int TENANT_ID = -1234;
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String TEST_POLICY_NAME = "TestPolicy";
    private static final String TEST_RULE_ID = UUID.randomUUID().toString();

    private PolicyManagementDAOImpl policyManagementDAO;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private String createdPolicyId;

    @BeforeClass
    public void setUp() {

        policyManagementDAO = new PolicyManagementDAOImpl();
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantDomain(TENANT_ID))
                .thenReturn(TENANT_DOMAIN);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
    }

    @AfterClass
    public void tearDown() {

        identityTenantUtil.close();
    }

    @Test(priority = 1)
    public void testAddPolicy() throws PolicyManagementException {

        Policy policy = new Policy(
                UUID.randomUUID().toString(),
                TEST_POLICY_NAME,
                TEST_RULE_ID,
                TENANT_DOMAIN,
                null);

        Policy result = policyManagementDAO.addPolicy(policy, TENANT_ID);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getName(), TEST_POLICY_NAME);
        Assert.assertEquals(result.getRuleId(), TEST_RULE_ID);

        createdPolicyId = result.getId();
    }

    @Test(priority = 2, dependsOnMethods = {"testAddPolicy"})
    public void testGetPolicyById() throws PolicyManagementException {

        Policy result = policyManagementDAO.getPolicyById(createdPolicyId, TENANT_ID);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getId(), createdPolicyId);
        Assert.assertEquals(result.getName(), TEST_POLICY_NAME);
        Assert.assertEquals(result.getRuleId(), TEST_RULE_ID);
    }

    @Test(priority = 3, dependsOnMethods = {"testAddPolicy"})
    public void testUpdatePolicy() throws PolicyManagementException {

        String updatedName = "UpdatedPolicy";
        String updatedRuleId = UUID.randomUUID().toString();

        Policy updatedPolicy = new Policy(
                createdPolicyId,
                updatedName,
                updatedRuleId,
                TENANT_DOMAIN,
                null);

        Policy result = policyManagementDAO.updatePolicy(updatedPolicy, TENANT_ID);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getName(), updatedName);
        Assert.assertEquals(result.getRuleId(), updatedRuleId);
    }

    @Test(priority = 4, dependsOnMethods = {"testAddPolicy"})
    public void testGetPolicyById_NotFound() throws PolicyManagementException {

        Policy result = policyManagementDAO.getPolicyById(
                UUID.randomUUID().toString(), TENANT_ID);

        Assert.assertNull(result);
    }

    @Test(priority = 5, dependsOnMethods = {"testAddPolicy"})
    public void testDeletePolicy() throws PolicyManagementException {

        policyManagementDAO.deletePolicy(createdPolicyId, TENANT_ID);

        Policy result = policyManagementDAO.getPolicyById(createdPolicyId, TENANT_ID);
        Assert.assertNull(result);
    }
}
