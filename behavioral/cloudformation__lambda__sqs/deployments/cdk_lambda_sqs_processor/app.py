#!/usr/bin/env python3
"""CDK app: one SQS queue, one Lambda Function wired to it with `SqsEventSource`.

The handler echoes each record's body onto a second, check-owned queue (`marker_queue_url`) so
the check can read back that the message was actually processed.

Context (env):
  account, region     -- the deploy target
  qualifier           -- bootstrap qualifier (DefaultStackSynthesizer)
  stack_name          -- the stack id
  marker              -- stamped onto every marker message, so it is provably this run's
  marker_queue_url     -- the check-owned queue the handler reports to
  marker_queue_arn     -- same queue, by ARN, so the stack can grant SendMessage on it
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_lambda_event_sources as event_sources
from aws_cdk import aws_sqs as sqs

HANDLER = """
import json
import os

import boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    for record in event.get("Records", []):
        body = json.loads(record["body"])
        _sqs.send_message(
            QueueUrl=os.environ["MARKER_QUEUE_URL"],
            MessageBody=json.dumps({"marker": os.environ["MARKER"], "echo": body}),
        )
    return {"processed": len(event.get("Records", []))}
"""


class SqsProcessorStack(cdk.Stack):
    def __init__(self, scope, sid, *, marker: str, marker_queue_url: str, marker_queue_arn: str,
                **kwargs):
        super().__init__(scope, sid, **kwargs)
        source_queue = sqs.Queue(self, "SourceQueue", visibility_timeout=cdk.Duration.seconds(60))
        marker_queue = sqs.Queue.from_queue_arn(self, "MarkerQueue", marker_queue_arn)
        fn = _lambda.Function(
            self, "ConsumerFn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER),
            timeout=cdk.Duration.seconds(30),
            environment={"MARKER": marker, "MARKER_QUEUE_URL": marker_queue_url},
        )
        marker_queue.grant_send_messages(fn)
        fn.add_event_source(event_sources.SqsEventSource(source_queue, batch_size=1))
        cdk.CfnOutput(self, "SourceQueueUrl", value=source_queue.queue_url)
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])
synthesizer = cdk.DefaultStackSynthesizer(qualifier=os.environ["QUALIFIER"])
SqsProcessorStack(
    app, os.environ["STACK_NAME"], env=env, synthesizer=synthesizer,
    marker=os.environ["MARKER"],
    marker_queue_url=os.environ["MARKER_QUEUE_URL"],
    marker_queue_arn=os.environ["MARKER_QUEUE_ARN"],
)
app.synth()
