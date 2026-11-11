"""cdk-rule-sqs-target - an events.Rule with a targets.SqsQueue, matched by a custom detail-type."""
import os

import aws_cdk as cdk
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_sqs as sqs


class RuleQueueStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        queue = sqs.Queue(self, "Queue", removal_policy=cdk.RemovalPolicy.DESTROY)
        rule = events.Rule(
            self, "Rule",
            event_pattern=events.EventPattern(
                source=["sim2real.cdkrulesqs"],
                detail_type=["sim2real.watched"],
            ),
        )
        rule.add_target(targets.SqsQueue(queue))
        cdk.CfnOutput(self, "RuleName", value=rule.rule_name)
        cdk.CfnOutput(self, "QueueUrl", value=queue.queue_url)
        cdk.CfnOutput(self, "QueueArn", value=queue.queue_arn)
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
RuleQueueStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
