package org.wso2.carbon.identity.device.policy.management.internal.rule;

import org.wso2.carbon.identity.rule.evaluation.api.exception.RuleEvaluationDataProviderException;
import org.wso2.carbon.identity.rule.evaluation.api.model.Field;
import org.wso2.carbon.identity.rule.evaluation.api.model.FieldValue;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.FlowType;
import org.wso2.carbon.identity.rule.evaluation.api.model.RuleEvaluationContext;
import org.wso2.carbon.identity.rule.evaluation.api.model.ValueType;
import org.wso2.carbon.identity.rule.evaluation.api.provider.RuleEvaluationDataProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DevicePolicyEvaluationDataProvider implements RuleEvaluationDataProvider {

    @Override
    public FlowType getSupportedFlowType() {

        return FlowType.DEVICE_POLICY;
    }

    @Override
    public List<FieldValue> getEvaluationData(RuleEvaluationContext ruleEvaluationContext,
                                              FlowContext flowContext, String tenantDomain)
            throws RuleEvaluationDataProviderException {

        Map<String, Object> deviceData = flowContext.getContextData();
        List<FieldValue> fieldValues = new ArrayList<>();

        for (Field field : ruleEvaluationContext.getFields()) {
            String value = (String) deviceData.get(field.getName());
            if (value != null) {
                fieldValues.add(new FieldValue(field.getName(), value, ValueType.STRING));
            }
        }

        return fieldValues;
    }
}