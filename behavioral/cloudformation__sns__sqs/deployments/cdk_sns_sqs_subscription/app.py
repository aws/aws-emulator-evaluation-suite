"""cdk-sns-sqs-subscription - an sns.Topic with an SqsSubscription; CDK writes the queue policy."""
import os

import aws_cdk as cdk
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from aws_cdk import aws_sqs as sqs


class TopicQueueStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        topic = sns.Topic(self, "Topic")
        queue = sqs.Queue(self, "Queue", removal_policy=cdk.RemovalPolicy.DESTROY)
        topic.add_subscription(subs.SqsSubscription(queue))
        cdk.CfnOutput(self, "TopicArn", value=topic.topic_arn)
        cdk.CfnOutput(self, "QueueUrl", value=queue.queue_url)
        cdk.CfnOutput(self, "QueueArn", value=queue.queue_arn)
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
TopicQueueStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
