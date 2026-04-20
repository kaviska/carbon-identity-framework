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

package org.wso2.carbon.identity.device.policy.management.api.model;

import org.wso2.carbon.identity.rule.management.api.model.Rule;

/**
 * Model class representing a Device Policy.
 */
public class Policy {

    private final String id;
    private final String name;
    private final String ruleId;
    private final String tenantDomain;
    private final Rule rule;

    public Policy(String id, String name, String ruleId, String tenantDomain, Rule rule) {

        this.id = id;
        this.name = name;
        this.ruleId = ruleId;
        this.tenantDomain = tenantDomain;
        this.rule = rule;
    }

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getRuleId() {

        return ruleId;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public Rule getRule() {

        return rule;
    }
}
