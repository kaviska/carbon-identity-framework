/*
* Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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
* KIND, either express or implied. See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.identity.device.mgt.internal.constant;

/**
 * SQL constants used by the device management DAO layer.
 */
public class DeviceMgtSQLConstants {

    private DeviceMgtSQLConstants() {
    }

    /**
     * Column and named-parameter names.
     */
    public static class Column {

        public static final String ID = "ID";
        public static final String USER_ID = "USER_ID";
        public static final String DEVICE_NAME = "DEVICE_NAME";
        public static final String DEVICE_MODEL = "DEVICE_MODEL";
        public static final String PUBLIC_KEY = "PUBLIC_KEY";
        public static final String STATUS = "STATUS";
        public static final String REGISTERED_AT = "REGISTERED_AT";
        public static final String METADATA = "METADATA";
        public static final String TENANT_ID = "TENANT_ID";

        private Column() {
        }
    }

    /**
     * SQL query definitions.
     */
    public static class Query {

        public static final String REGISTER_DEVICE =
                "INSERT INTO IDN_REGISTERED_DEVICE " +
                        "(ID, USER_ID, DEVICE_NAME, DEVICE_MODEL, PUBLIC_KEY, STATUS, REGISTERED_AT, " +
                        "TENANT_ID, METADATA) " +
                        "VALUES (:ID;, :USER_ID;, :DEVICE_NAME;, :DEVICE_MODEL;, :PUBLIC_KEY;, :STATUS;, " +
                        ":REGISTERED_AT;, :TENANT_ID;, :METADATA;)";

        public static final String GET_DEVICE_BY_ID =
                "SELECT ID, USER_ID, DEVICE_NAME, DEVICE_MODEL, PUBLIC_KEY, STATUS, REGISTERED_AT, " +
                        "METADATA, TENANT_ID " +
                        "FROM IDN_REGISTERED_DEVICE " +
                        "WHERE ID = :ID; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_DEVICES_BY_USER_ID =
                "SELECT ID, USER_ID, DEVICE_NAME, DEVICE_MODEL, PUBLIC_KEY, STATUS, REGISTERED_AT, " +
                        "METADATA, TENANT_ID " +
                        "FROM IDN_REGISTERED_DEVICE " +
                        "WHERE USER_ID = :USER_ID; AND STATUS = 'ACTIVE' AND TENANT_ID = :TENANT_ID; " +
                        "ORDER BY REGISTERED_AT DESC";

        public static final String UPDATE_DEVICE_NAME =
                "UPDATE IDN_REGISTERED_DEVICE SET DEVICE_NAME = :DEVICE_NAME; " +
                        "WHERE ID = :ID; AND TENANT_ID = :TENANT_ID;";

        public static final String GET_ALL_DEVICES =
                "SELECT ID, USER_ID, DEVICE_NAME, DEVICE_MODEL, PUBLIC_KEY, STATUS, REGISTERED_AT, " +
                        "METADATA, TENANT_ID " +
                        "FROM IDN_REGISTERED_DEVICE " +
                        "WHERE TENANT_ID = :TENANT_ID; ORDER BY REGISTERED_AT DESC";

        public static final String DELETE_DEVICE =
                "DELETE FROM IDN_REGISTERED_DEVICE " +
                        "WHERE ID = :ID; AND TENANT_ID = :TENANT_ID;";

        private Query() {
        }
    }
}


