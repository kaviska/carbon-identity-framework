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

package org.wso2.carbon.identity.device.policy.internal.component;

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
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.client.attestation.mgt.services.ClientAttestationService;
import org.wso2.carbon.identity.device.mgt.api.service.DeviceManagementService;
import org.wso2.carbon.identity.device.policy.api.service.DevicePolicyEvaluator;
import org.wso2.carbon.identity.device.policy.api.service.IntegrityDataEnricher;
import org.wso2.carbon.identity.device.policy.internal.js.DevicePolicyJsFunction;
import org.wso2.carbon.identity.device.policy.internal.rule.DevicePolicyEvaluationDataProvider;
import org.wso2.carbon.identity.device.policy.internal.service.impl.DevicePolicyEvaluatorImpl;
import org.wso2.carbon.identity.device.policy.internal.service.impl.IntegrityDataEnricherImpl;
import org.wso2.carbon.identity.policy.management.api.service.PolicyManagementService;
import org.wso2.carbon.identity.rule.evaluation.api.provider.RuleEvaluationDataProvider;
import org.wso2.carbon.identity.rule.evaluation.api.service.RuleEvaluationService;

/**
 * OSGi DS component for the device policy bundle.
 * Registers DevicePolicyEvaluator, IntegrityDataEnricher, RuleEvaluationDataProvider,
 * and the isDevicePolicyCompliant JS function.
 */
@Component(
        name = "device.policy.service.component",
        immediate = true
)
public class DevicePolicyServiceComponent {

    private static final Log LOG = LogFactory.getLog(DevicePolicyServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleCtx = context.getBundleContext();

            DevicePolicyEvaluator devicePolicyEvaluator = new DevicePolicyEvaluatorImpl();
            IntegrityDataEnricher integrityDataEnricher = new IntegrityDataEnricherImpl();

            bundleCtx.registerService(DevicePolicyEvaluator.class.getName(), devicePolicyEvaluator, null);
            bundleCtx.registerService(IntegrityDataEnricher.class.getName(), integrityDataEnricher, null);
            bundleCtx.registerService(RuleEvaluationDataProvider.class.getName(),
                    new DevicePolicyEvaluationDataProvider(), null);

            DevicePolicyComponentServiceHolder holder = DevicePolicyComponentServiceHolder.getInstance();
            holder.setDevicePolicyEvaluator(devicePolicyEvaluator);
            holder.setIntegrityDataEnricher(integrityDataEnricher);

            holder.getJsFunctionRegistry().register(
                    JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER,
                    "isDevicePolicyCompliant",
                    new DevicePolicyJsFunction());

            LOG.debug("Device policy bundle activated.");
        } catch (Throwable e) {
            LOG.error("Error while initializing device policy service component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        LOG.debug("Device policy bundle deactivated.");
    }

    @Reference(
            name = "policy.management.service",
            service = PolicyManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetPolicyManagementService"
    )
    protected void setPolicyManagementService(PolicyManagementService policyManagementService) {

        DevicePolicyComponentServiceHolder.getInstance().setPolicyManagementService(policyManagementService);
        LOG.debug("PolicyManagementService set in Device Policy component.");
    }

    protected void unsetPolicyManagementService(PolicyManagementService policyManagementService) {

        DevicePolicyComponentServiceHolder.getInstance().setPolicyManagementService(null);
        LOG.debug("PolicyManagementService unset in Device Policy component.");
    }

    @Reference(
            name = "device.management.service",
            service = DeviceManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetDeviceManagementService"
    )
    protected void setDeviceManagementService(DeviceManagementService deviceManagementService) {

        DevicePolicyComponentServiceHolder.getInstance().setDeviceManagementService(deviceManagementService);
        LOG.debug("DeviceManagementService set in Device Policy component.");
    }

    protected void unsetDeviceManagementService(DeviceManagementService deviceManagementService) {

        DevicePolicyComponentServiceHolder.getInstance().setDeviceManagementService(null);
        LOG.debug("DeviceManagementService unset in Device Policy component.");
    }

    @Reference(
            name = "rule.evaluation.service",
            service = RuleEvaluationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRuleEvaluationService"
    )
    protected void setRuleEvaluationService(RuleEvaluationService ruleEvaluationService) {

        DevicePolicyComponentServiceHolder.getInstance().setRuleEvaluationService(ruleEvaluationService);
        LOG.debug("RuleEvaluationService set in Device Policy component.");
    }

    protected void unsetRuleEvaluationService(RuleEvaluationService ruleEvaluationService) {

        DevicePolicyComponentServiceHolder.getInstance().setRuleEvaluationService(null);
        LOG.debug("RuleEvaluationService unset in Device Policy component.");
    }

    @Reference(
            name = "js.function.registry",
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    protected void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        DevicePolicyComponentServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
        LOG.debug("JsFunctionRegistry set in Device Policy component.");
    }

    protected void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        DevicePolicyComponentServiceHolder.getInstance().setJsFunctionRegistry(null);
        LOG.debug("JsFunctionRegistry unset in Device Policy component.");
    }

    @Reference(
            name = "client.attestation.service",
            service = ClientAttestationService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClientAttestationService"
    )
    protected void setClientAttestationService(ClientAttestationService clientAttestationService) {

        DevicePolicyComponentServiceHolder.getInstance().setClientAttestationService(clientAttestationService);
        LOG.debug("ClientAttestationService set in Device Policy component.");
    }

    protected void unsetClientAttestationService(ClientAttestationService clientAttestationService) {

        DevicePolicyComponentServiceHolder.getInstance().setClientAttestationService(null);
        LOG.debug("ClientAttestationService unset in Device Policy component.");
    }
}
