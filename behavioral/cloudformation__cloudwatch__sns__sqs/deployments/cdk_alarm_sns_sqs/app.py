#!/usr/bin/env python3
"""CDK app: a metric alarm with an SNS action, and an SQS subscription on the topic.

Context: stack_name, account, region, qualifier, metric_namespace, metric_name, alarm_name.
"""

import aws_cdk as cdk
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from aws_cdk import aws_sqs as sqs

app = cdk.App()
ctx = app.node.get_context
stack = cdk.Stack(
    app,
    ctx("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier")),
    env=cdk.Environment(account=ctx("account"), region=ctx("region")),
)

queue = sqs.Queue(stack, "Queue")
topic = sns.Topic(stack, "Topic")
topic.add_subscription(sns_subscriptions.SqsSubscription(queue))

metric = cloudwatch.Metric(
    namespace=ctx("metric_namespace"), metric_name=ctx("metric_name"), statistic="Sum"
)
alarm = cloudwatch.Alarm(
    stack,
    "Alarm",
    alarm_name=ctx("alarm_name"),
    metric=metric,
    threshold=1,
    evaluation_periods=1,
    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
)
alarm.add_alarm_action(cloudwatch_actions.SnsAction(topic))

cdk.CfnOutput(stack, "QueueUrl", value=queue.queue_url)
cdk.CfnOutput(stack, "TopicArn", value=topic.topic_arn)
cdk.CfnOutput(stack, "AlarmName", value=alarm.alarm_name)
app.synth()
