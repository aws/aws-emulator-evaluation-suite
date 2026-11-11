#!/usr/bin/env python3
"""CDK app: two metric alarms and a composite alarm over them.

Context: stack_name, account, region, qualifier, rule_type ("any" or "all"), metric_namespace,
alarm1_name, alarm2_name, composite_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_cloudwatch as cloudwatch

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)

namespace = ctx("metric_namespace")


def _alarm(node_id: str, alarm_name: str, metric_name: str) -> cloudwatch.Alarm:
    metric = cloudwatch.Metric(namespace=namespace, metric_name=metric_name, statistic="Sum")
    return cloudwatch.Alarm(
        stack,
        node_id,
        alarm_name=alarm_name,
        metric=metric,
        threshold=1,
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        # The metrics never get data; IGNORE keeps each state SetAlarmState sets.
        treat_missing_data=cloudwatch.TreatMissingData.IGNORE,
    )


alarm1 = _alarm("Alarm1", ctx("alarm1_name"), "Metric1")
alarm2 = _alarm("Alarm2", ctx("alarm2_name"), "Metric2")

rule = (
    cloudwatch.AlarmRule.any_of(alarm1, alarm2)
    if ctx("rule_type") == "any"
    else cloudwatch.AlarmRule.all_of(alarm1, alarm2)
)

composite = cloudwatch.CompositeAlarm(
    stack, "Composite", composite_alarm_name=ctx("composite_name"), alarm_rule=rule
)

cdk.CfnOutput(stack, "Alarm1Name", value=alarm1.alarm_name)
cdk.CfnOutput(stack, "Alarm2Name", value=alarm2.alarm_name)
cdk.CfnOutput(stack, "CompositeName", value=composite.alarm_name)
app.synth()
