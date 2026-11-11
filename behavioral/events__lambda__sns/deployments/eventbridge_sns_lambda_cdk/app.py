#!/usr/bin/env python3
"""CDK app: an EventBridge rule on a custom bus targets an SNS topic, which a Lambda subscribes to.

Context values (passed via `cdk synth --context ...`):
  bus_name: the custom event bus the stack creates.
  source: the event source the rule matches.
  queue_url / queue_arn: an SQS queue (created outside this stack) that the Lambda forwards every
      invocation event into, so the check can observe that the chain delivered.
"""

from aws_cdk import App, CfnOutput, Duration, Stack
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from aws_cdk import aws_sqs as sqs

HANDLER_CODE = """
import boto3, json, os
sqs = boto3.client('sqs')
def handler(event, context):
    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))
    return {'ok': True}
"""


class EventBridgeSnsLambdaStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        queue_url = self.node.try_get_context("queue_url")
        queue_arn = self.node.try_get_context("queue_arn")

        bus = events.EventBus(self, "Bus", event_bus_name=self.node.try_get_context("bus_name"))
        topic = sns.Topic(self, "Topic")
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER_CODE),
            timeout=Duration.seconds(15),
            environment={"QUEUE_URL": queue_url},
        )
        sqs.Queue.from_queue_arn(self, "SinkQueue", queue_arn).grant_send_messages(fn)
        topic.add_subscription(subs.LambdaSubscription(fn))

        # The SnsTopic target adds the topic policy that lets events.amazonaws.com publish.
        rule = events.Rule(
            self,
            "Rule",
            event_bus=bus,
            event_pattern=events.EventPattern(
                source=[self.node.try_get_context("source")], detail_type=["order.placed"]
            ),
        )
        rule.add_target(targets.SnsTopic(topic))

        CfnOutput(self, "TopicArn", value=topic.topic_arn)
        CfnOutput(self, "FunctionName", value=fn.function_name)
        CfnOutput(self, "BusName", value=bus.event_bus_name)
        CfnOutput(self, "RuleArn", value=rule.rule_arn)


app = App()
EventBridgeSnsLambdaStack(app, "EventBridgeSnsLambdaStack")
app.synth()
