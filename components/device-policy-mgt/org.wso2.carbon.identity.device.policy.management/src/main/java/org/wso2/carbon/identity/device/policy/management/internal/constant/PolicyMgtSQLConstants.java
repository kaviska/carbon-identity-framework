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

package org.wso2.carbon.identity.device.policy.management.internal.constant;

/**
 * SQL constants for Policy Management DAO.
 * Three tables: IDN_POLICY (main), IDN_POLICY_RULE (M:N with rule-mgt), IDN_POLICY_ACTION (M:N with action-mgt).
 */
public class PolicyMgtSQLConstants {

    private PolicyMgtSQLConstants() {

    }

    /**
     * SQL column name constants.
     */
    public static class Column {

        public static final String ID = "ID";
        public static final String POLICY_ID = "POLICY_ID";
        public static final String POLICY_NAME = "POLICY_NAME";
        public static final String TENANT_ID = "TENANT_ID";
        public static final String RULE_ID = "RULE_ID";
        public static final String PLATFORM = "PLATFORM";
        public static final String ACTION_ID = "ACTION_ID";
        public static final String ACTION_TYPE = "ACTION_TYPE";
        public static final String EXEC_ORDER = "EXEC_ORDER";

        private Column() {

        }
    }

    /**
     * SQL query constants for IDN_POLICY, IDN_POLICY_RULE, and IDN_POLICY_ACTION.
     */
    public static class Query {

        // IDN_POLICY table.
        public static final String ADD_POLICY =
                "INSERT INTO IDN_POLICY (ID, POLICY_NAME, TENANT_ID) " +
                        "VALUES (:ID;, :POLICY_NAME;, :TENANT_ID;)";

        public static final String UPDATE_POLICY =
                "UPDATE IDN_POLICY SET POLICY_NAME = :POLICY_NAME; " +
                        "WHERE ID = :POLICY_ID; AND TENANT_ID = :TENANT_ID;";

        public static final String DELETE_POLICY =
                "DELETE FROM IDN_POLICY WHERE ID = :POLICY_ID; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_POLICY_BY_ID =
                "SELECT ID, POLICY_NAME FROM IDN_POLICY " +
                        "WHERE ID = :POLICY_ID; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_POLICY_BY_NAME =
                "SELECT ID, POLICY_NAME FROM IDN_POLICY " +
                        "WHERE POLICY_NAME = :POLICY_NAME; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_ALL_POLICIES =
                "SELECT ID, POLICY_NAME FROM IDN_POLICY " +
                        "WHERE TENANT_ID = :TENANT_ID; ORDER BY POLICY_NAME ASC";

        // IDN_POLICY_RULE junction table.
        public static final String ADD_POLICY_RULE =
                "INSERT INTO IDN_POLICY_RULE (ID, POLICY_ID, RULE_ID, PLATFORM) " +
                        "VALUES (:ID;, :POLICY_ID;, :RULE_ID;, :PLATFORM;)";

        public static final String GET_POLICY_RULES =
                "SELECT ID, RULE_ID, PLATFORM FROM IDN_POLICY_RULE " +
                        "WHERE POLICY_ID = :POLICY_ID;";

        public static final String DELETE_POLICY_RULES =
                "DELETE FROM IDN_POLICY_RULE WHERE POLICY_ID = :POLICY_ID;";

        // IDN_POLICY_ACTION junction table.
        public static final String ADD_POLICY_ACTION =
                "INSERT INTO IDN_POLICY_ACTION (ID, POLICY_ID, ACTION_ID, ACTION_TYPE, EXEC_ORDER) " +
                        "VALUES (:ID;, :POLICY_ID;, :ACTION_ID;, :ACTION_TYPE;, :EXEC_ORDER;)";

        public static final String GET_POLICY_ACTIONS =
                "SELECT ID, ACTION_ID, ACTION_TYPE, EXEC_ORDER FROM IDN_POLICY_ACTION " +
                        "WHERE POLICY_ID = :POLICY_ID; ORDER BY EXEC_ORDER ASC";

        public static final String DELETE_POLICY_ACTIONS =
                "DELETE FROM IDN_POLICY_ACTION WHERE POLICY_ID = :POLICY_ID;";

        private Query() {

        }
    }
}
