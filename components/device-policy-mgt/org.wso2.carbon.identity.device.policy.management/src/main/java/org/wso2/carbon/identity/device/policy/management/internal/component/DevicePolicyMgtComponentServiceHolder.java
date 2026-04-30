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

package org.wso2.carbon.identity.device.policy.management.internal.component;

import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.rule.evaluation.api.service.RuleEvaluationService;
import org.wso2.carbon.identity.rule.management.api.service.RuleManagementService;
import org.wso2.carbon.identity.device.policy.management.api.service.PolicyManagementService;
import org.wso2.carbon.identity.device.mgt.api.service.DeviceManagementService;


/**
 * Service holder for Device Policy Management component.
 */
public class DevicePolicyMgtComponentServiceHolder {

    private static final DevicePolicyMgtComponentServiceHolder INSTANCE =
            new DevicePolicyMgtComponentServiceHolder();
    private RuleManagementService ruleManagementService;
    private RuleEvaluationService ruleEvaluationService;
    private PolicyManagementService policyManagementService;
    private JsFunctionRegistry jsFunctionRegistry;
    private DeviceManagementService deviceManagementService;


    private DevicePolicyMgtComponentServiceHolder() {

    }

    public static DevicePolicyMgtComponentServiceHolder getInstance() {

        return INSTANCE;
    }

    public RuleManagementService getRuleManagementService() {

        return ruleManagementService;
    }

    public void setRuleManagementService(RuleManagementService ruleManagementService) {

        this.ruleManagementService = ruleManagementService;
    }

    public RuleEvaluationService getRuleEvaluationService() {
        return ruleEvaluationService;
    }

    public void setRuleEvaluationService(RuleEvaluationService ruleEvaluationService) {
        this.ruleEvaluationService = ruleEvaluationService;
    }

    public PolicyManagementService getPolicyManagementService() {

        return policyManagementService;
    }

    public void setPolicyManagementService(PolicyManagementService policyManagementService) {

        this.policyManagementService = policyManagementService;
    }

    public JsFunctionRegistry getJsFunctionRegistry() {

        return jsFunctionRegistry;
    }

    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = jsFunctionRegistry;
    }

    public DeviceManagementService getDeviceManagementService() {
        return deviceManagementService;
    }

    public void setDeviceManagementService(DeviceManagementService deviceManagementService) {
        this.deviceManagementService = deviceManagementService;
    }
}
