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

package org.wso2.carbon.identity.device.policy.management.api.model;

/**
 * Association between a Policy and an Action with execution order.
 */
public class PolicyAction {

    private final String id;
    private final String actionId;
    private final String actionType;
    private final int execOrder;

    public PolicyAction(String id, String actionId, String actionType, int execOrder) {

        this.id = id;
        this.actionId = actionId;
        this.actionType = actionType;
        this.execOrder = execOrder;
    }

    public String getId() {

        return id;
    }

    public String getActionId() {

        return actionId;
    }

    public String getActionType() {

        return actionType;
    }

    public int getExecOrder() {

        return execOrder;
    }
}
