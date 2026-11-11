#!/usr/bin/env python3
"""CDK app: a log group with two metric filters over it, and an alarm on each filter's metric.

Context: stack_name, account, region, qualifier, metric_namespace, and per filter its pattern,
metric name and alarm name: filter_pattern, metric_name, alarm_name for the graded filter and
contrast_pattern, contrast_metric_name, contrast_alarm_name for the contrast one.
"""

import aws_cdk as cdk
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_logs as logs

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)

log_group = logs.LogGroup(stack, "LogGroup", removal_policy=cdk.RemovalPolicy.DESTROY)



def _filter_alarm(prefix: str, pattern: str, metric_name: str, alarm_name: str):
    """A metric filter counting lines that match ``pattern`` and a 60 s Sum >= 1 alarm on it."""
    metric_filter = logs.MetricFilter(
        stack,
        f"{prefix}Filter",
        log_group=log_group,
        filter_pattern=logs.FilterPattern.literal(pattern),
        metric_namespace=ctx("metric_namespace"),
        metric_name=metric_name,
        metric_value="1",
    )
    return cloudwatch.Alarm(
        stack,
        f"{prefix}Alarm",
        alarm_name=alarm_name,
        metric=metric_filter.metric(statistic="Sum", period=cdk.Duration.seconds(60)),
        threshold=1,
        evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
    )


alarm = _filter_alarm("Match", ctx("filter_pattern"), ctx("metric_name"), ctx("alarm_name"))
contrast = _filter_alarm(
    "Contrast", ctx("contrast_pattern"), ctx("contrast_metric_name"), ctx("contrast_alarm_name")
)

cdk.CfnOutput(stack, "LogGroupName", value=log_group.log_group_name)
cdk.CfnOutput(stack, "AlarmName", value=alarm.alarm_name)
cdk.CfnOutput(stack, "ContrastAlarmName", value=contrast.alarm_name)
app.synth()
