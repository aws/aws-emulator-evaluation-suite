"""cdk-kms-sqs - a KMS Key with an Alias used for SQS server-side encryption."""
import os

import aws_cdk as cdk
from aws_cdk import aws_kms as kms
from aws_cdk import aws_sqs as sqs


class KmsSqsStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        key = kms.Key(
            self, "Key",
            pending_window=cdk.Duration.days(7),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        alias = key.add_alias(os.environ["KEY_ALIAS"])
        queue = sqs.Queue(
            self, "Queue",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=key,
        )
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])
        cdk.CfnOutput(self, "KeyId", value=key.key_id)
        cdk.CfnOutput(self, "AliasName", value=alias.alias_name)
        cdk.CfnOutput(self, "QueueUrl", value=queue.queue_url)


app = cdk.App()
KmsSqsStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"],
    ),
)
app.synth()
