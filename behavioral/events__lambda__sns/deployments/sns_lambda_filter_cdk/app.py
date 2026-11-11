#!/usr/bin/env python3
"""CDK app: SNS topic subscribed by a Lambda function through a message-attribute filter policy.

Context values (passed via `cdk synth --context ...`):
  queue_url / queue_arn: an SQS queue (created outside this stack) that the Lambda forwards every
      invocation event into, so the check can observe which notifications reached the function.
"""

from aws_cdk import App, CfnOutput, Duration, Stack
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


class SnsLambdaFilterStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        queue_url = self.node.try_get_context("queue_url")
        queue_arn = self.node.try_get_context("queue_arn")

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

        # Only notifications whose "kind" attribute is "keep" reach the function.
        sub = subs.LambdaSubscription(
            fn,
            filter_policy={"kind": sns.SubscriptionFilter.string_filter(allowlist=["keep"])},
        )
        topic.add_subscription(sub)

        CfnOutput(self, "TopicArn", value=topic.topic_arn)
        CfnOutput(self, "FunctionName", value=fn.function_name)


app = App()
SnsLambdaFilterStack(app, "SnsLambdaFilterStack")
app.synth()
