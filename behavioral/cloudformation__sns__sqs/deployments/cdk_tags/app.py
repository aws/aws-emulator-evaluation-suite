#!/usr/bin/env python3
"""Asset-free CDK app: one stack with an SQS Queue and an SNS Topic, tagged two ways.

`Tags.of(stack).add(...)` sets a construct-level tag that CDK's Aspect system writes onto the
Properties.Tags of every taggable resource in the synthesized template. The CLI's own `--tags`
flag (not represented in this app) sets tags on the CloudFormation stack itself, which
CloudFormation then propagates to the resources it creates.

Context:
  account, region  -- the environment
  stack             -- stack id
  queue_name        -- physical QueueName
  topic_name        -- physical TopicName
  tag_key, tag_value -- the construct-level tag Tags.of() applies
"""
import aws_cdk as cdk
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs


class TaggedStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, queue_name, topic_name, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.queue = sqs.Queue(self, "Queue", queue_name=queue_name)
        self.topic = sns.Topic(self, "Topic", topic_name=topic_name)
        cdk.CfnOutput(self, "QueueUrl", value=self.queue.queue_url)
        cdk.CfnOutput(self, "TopicArn", value=self.topic.topic_arn)


app = cdk.App()
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region"),
)

stack = TaggedStack(
    app, app.node.try_get_context("stack"),
    queue_name=app.node.try_get_context("queue_name"),
    topic_name=app.node.try_get_context("topic_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)
cdk.Tags.of(stack).add(
    app.node.try_get_context("tag_key"), app.node.try_get_context("tag_value"),
)

app.synth()
