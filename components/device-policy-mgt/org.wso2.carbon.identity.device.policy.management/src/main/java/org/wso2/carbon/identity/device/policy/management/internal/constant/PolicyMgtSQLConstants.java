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

package org.wso2.carbon.identity.device.policy.management.internal.constant;

/**
 * SQL constants for Policy Management DAO.
 */
public class PolicyMgtSQLConstants {

    private PolicyMgtSQLConstants() {

    }

    public static class Column {

        public static final String POLICY_ID = "POLICY_ID";
        public static final String POLICY_NAME = "POLICY_NAME";
        public static final String RULE_ID = "RULE_ID";
        public static final String TENANT_ID = "TENANT_ID";

        private Column() {

        }
    }

    public static class Query {

        public static final String ADD_POLICY =
                "INSERT INTO IDN_DEVICE_POLICY (POLICY_ID, POLICY_NAME, RULE_ID, TENANT_ID) " +
                        "VALUES (:POLICY_ID;, :POLICY_NAME;, :RULE_ID;, :TENANT_ID;)";

        public static final String UPDATE_POLICY =
                "UPDATE IDN_DEVICE_POLICY SET POLICY_NAME = :POLICY_NAME;, RULE_ID = :RULE_ID; " +
                        "WHERE POLICY_ID = :POLICY_ID; AND TENANT_ID = :TENANT_ID;";

        public static final String DELETE_POLICY =
                "DELETE FROM IDN_DEVICE_POLICY WHERE POLICY_ID = :POLICY_ID; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_POLICY_BY_ID =
                "SELECT POLICY_ID, POLICY_NAME, RULE_ID FROM IDN_DEVICE_POLICY " +
                        "WHERE POLICY_ID = :POLICY_ID; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_POLICY_BY_NAME =
                "SELECT POLICY_ID, POLICY_NAME, RULE_ID FROM IDN_DEVICE_POLICY " +
                        "WHERE POLICY_NAME = :POLICY_NAME; AND TENANT_ID = :TENANT_ID;";

        private Query() {

        }
    }
}
