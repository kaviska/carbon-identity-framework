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

package org.wso2.carbon.identity.device.policy.internal.constant;

/**
 * SQL constants used by the device token replay store and its cleanup task.
 */
public final class DevicePolicySQLConstants {

    private DevicePolicySQLConstants() {
    }

    /**
     * Column and named-parameter names.
     */
    public static final class Column {

        public static final String JTI = "JTI";
        public static final String TENANT_ID = "TENANT_ID";
        public static final String IAT = "IAT";
        public static final String EXPIRY_TIME = "EXPIRY_TIME";

        private Column() {
        }
    }

    /**
     * SQL query definitions for the device token replay store.
     */
    public static final class Query {

        public static final String IS_TOKEN_REPLAYED =
                "SELECT 1 FROM IDN_DEVICE_TOKEN_JTI " +
                        "WHERE JTI = :JTI; AND TENANT_ID = :TENANT_ID;";

        public static final String STORE_TOKEN_JTI =
                "INSERT INTO IDN_DEVICE_TOKEN_JTI " +
                        "(JTI, TENANT_ID, IAT, EXPIRY_TIME) " +
                        "VALUES (:JTI;, :TENANT_ID;, :IAT;, :EXPIRY_TIME;)";

        // Dialect-specific chunked delete queries for the cleanup task. The single bind parameter is the
        // cut-off timestamp; rows with EXPIRY_TIME older than it are removed. %d is the chunk (row) limit.
        public static final String DELETE_EXPIRED_TOKENS_MYSQL =
                "DELETE FROM IDN_DEVICE_TOKEN_JTI WHERE EXPIRY_TIME < ? LIMIT %d";

        public static final String DELETE_EXPIRED_TOKENS_MSSQL =
                "DELETE TOP (%d) FROM IDN_DEVICE_TOKEN_JTI WHERE EXPIRY_TIME < ?";

        public static final String DELETE_EXPIRED_TOKENS_POSTGRESQL =
                "DELETE FROM IDN_DEVICE_TOKEN_JTI WHERE CTID IN " +
                        "(SELECT CTID FROM IDN_DEVICE_TOKEN_JTI WHERE EXPIRY_TIME < ? LIMIT %d)";

        public static final String DELETE_EXPIRED_TOKENS_ORACLE =
                "DELETE FROM IDN_DEVICE_TOKEN_JTI WHERE ROWID IN " +
                        "(SELECT ROWID FROM IDN_DEVICE_TOKEN_JTI WHERE EXPIRY_TIME < ? AND ROWNUM <= %d)";

        public static final String DELETE_EXPIRED_TOKENS_DB2 =
                "DELETE FROM IDN_DEVICE_TOKEN_JTI WHERE (TENANT_ID, JTI) IN " +
                        "(SELECT TENANT_ID, JTI FROM IDN_DEVICE_TOKEN_JTI WHERE EXPIRY_TIME < ? " +
                        "FETCH FIRST %d ROWS ONLY)";

        private Query() {
        }
    }
}
