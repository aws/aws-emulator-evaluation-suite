#!/usr/bin/env python3
"""CDK app: SNS topic subscribed by a Lambda function.

Context values (passed via `cdk synth --context ...`):
  include_permission: "true" | "false" -- whether to use the high-level
      LambdaSubscription (which wires the required lambda:InvokeFunction
      permission for sns.amazonaws.com) or a bare CfnSubscription (which does
      not).
  queue_url / queue_arn: an SQS queue (created outside this stack) that the
      Lambda forwards every invocation event into, so the check can observe
      whether the function actually ran.
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


class SnsLambdaStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        include_permission = self.node.try_get_context("include_permission") == "true"
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
        imported_queue = sqs.Queue.from_queue_arn(self, "SinkQueue", queue_arn)
        imported_queue.grant_send_messages(fn)

        if include_permission:
            # High-level construct: wires the sns.amazonaws.com -> lambda:InvokeFunction
            # permission automatically.
            topic.add_subscription(subs.LambdaSubscription(fn))
        else:
            # Low-level L1 subscription: creates the SNS subscription but does NOT add the
            # matching Lambda resource policy statement.
            sns.CfnSubscription(
                self,
                "Sub",
                topic_arn=topic.topic_arn,
                endpoint=fn.function_arn,
                protocol="lambda",
            )

        CfnOutput(self, "TopicArn", value=topic.topic_arn)
        CfnOutput(self, "FunctionName", value=fn.function_name)


app = App()
SnsLambdaStack(app, "SnsLambdaStack")
app.synth()
