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

package org.wso2.carbon.identity.device.policy.management.internal.component;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.api.service.ActionVersioningHandler;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.device.mgt.api.service.DeviceManagementService;
import org.wso2.carbon.identity.device.policy.management.api.service.PolicyManagementService;
import org.wso2.carbon.identity.device.policy.management.internal.action.DevicePolicyActionRequestBuilder;
import org.wso2.carbon.identity.device.policy.management.internal.action.DevicePolicyActionResponseProcessor;
import org.wso2.carbon.identity.device.policy.management.internal.action.DevicePolicyActionVersioningHandler;
import org.wso2.carbon.identity.device.policy.management.internal.rule.DevicePolicyEvaluationDataProvider;
import org.wso2.carbon.identity.device.policy.management.internal.rule.DevicePolicyJsFunction;
import org.wso2.carbon.identity.device.policy.management.internal.service.impl.PolicyManagementServiceImpl;
import org.wso2.carbon.identity.rule.evaluation.api.provider.RuleEvaluationDataProvider;
import org.wso2.carbon.identity.rule.evaluation.api.service.RuleEvaluationService;
import org.wso2.carbon.identity.rule.management.api.service.RuleManagementService;

/**
 * Policy Management Service Component.
 * Registers policy management services and wires all required OSGi dependencies.
 */
@Component(
        name = "device.policy.management.service.component",
        immediate = true
)
public class DevicePolicyMgtServiceComponent {

    private static final Log LOG = LogFactory.getLog(DevicePolicyMgtServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleCtx = context.getBundleContext();
            PolicyManagementServiceImpl policyManagementService = PolicyManagementServiceImpl.getInstance();

            bundleCtx.registerService(PolicyManagementService.class.getName(), policyManagementService, null);
            bundleCtx.registerService(RuleEvaluationDataProvider.class.getName(),
                    new DevicePolicyEvaluationDataProvider(), null);

            // Register action-mgt integration services for DEVICE_POLICY action type.
            bundleCtx.registerService(ActionExecutionRequestBuilder.class.getName(),
                    new DevicePolicyActionRequestBuilder(), null);
            bundleCtx.registerService(ActionExecutionResponseProcessor.class.getName(),
                    new DevicePolicyActionResponseProcessor(), null);
            bundleCtx.registerService(ActionVersioningHandler.class.getName(),
                    new DevicePolicyActionVersioningHandler(), null);

            DevicePolicyMgtComponentServiceHolder.getInstance().setPolicyManagementService(policyManagementService);

            // Register the device policy compliance function with the JS function registry.
            DevicePolicyMgtComponentServiceHolder.getInstance().getJsFunctionRegistry()
                    .register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                            "isDevicePolicyCompliant",
                            new DevicePolicyJsFunction());

            LOG.debug("Policy management bundle activated.");
        } catch (Throwable e) {
            LOG.error("Error while initializing policy management service component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.debug("Policy management bundle deactivated.");
    }

    @Reference(
            name = "rule.management.service",
            service = RuleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRuleManagementService"
    )
    protected void setRuleManagementService(RuleManagementService ruleManagementService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setRuleManagementService(ruleManagementService);
        LOG.debug("RuleManagementService set in Policy Management component.");
    }

    protected void unsetRuleManagementService(RuleManagementService ruleManagementService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setRuleManagementService(null);
        LOG.debug("RuleManagementService unset in Policy Management component.");
    }

    @Reference(
            name = "rule.evaluation.service",
            service = RuleEvaluationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRuleEvaluationService"
    )
    protected void setRuleEvaluationService(RuleEvaluationService ruleEvaluationService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setRuleEvaluationService(ruleEvaluationService);
        LOG.debug("RuleEvaluationService set in Policy Management component.");
    }

    protected void unsetRuleEvaluationService(RuleEvaluationService ruleEvaluationService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setRuleEvaluationService(null);
        LOG.debug("RuleEvaluationService unset in Policy Management component.");
    }

    @Reference(
            name = "js.function.registry",
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    protected void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
        LOG.debug("JsFunctionRegistry set in Policy Management component.");
    }

    protected void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setJsFunctionRegistry(null);
        LOG.debug("JsFunctionRegistry unset in Policy Management component.");
    }

    @Reference(
            name = "device.management.service",
            service = DeviceManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetDeviceManagementService"
    )
    protected void setDeviceManagementService(DeviceManagementService deviceManagementService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setDeviceManagementService(deviceManagementService);
        LOG.debug("DeviceManagementService set in Policy Management component.");
    }

    protected void unsetDeviceManagementService(DeviceManagementService deviceManagementService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setDeviceManagementService(null);
        LOG.debug("DeviceManagementService unset in Policy Management component.");
    }

    @Reference(
            name = "action.executor.service",
            service = ActionExecutorService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetActionExecutorService"
    )
    protected void setActionExecutorService(ActionExecutorService actionExecutorService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setActionExecutorService(actionExecutorService);
        LOG.debug("ActionExecutorService set in Policy Management component.");
    }

    protected void unsetActionExecutorService(ActionExecutorService actionExecutorService) {

        DevicePolicyMgtComponentServiceHolder.getInstance().setActionExecutorService(null);
        LOG.debug("ActionExecutorService unset in Policy Management component.");
    }
}
