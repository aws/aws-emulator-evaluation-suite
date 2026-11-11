#!/usr/bin/env python3
"""Asset-free CDK app: two S3 Buckets that differ ONLY in `auto_delete_objects`.

  Auto   -- removal_policy=DESTROY, auto_delete_objects=True. CDK attaches a
            Custom::S3AutoDeleteObjects resource backed by an inline-code Lambda that empties the
            bucket before CloudFormation deletes it.
  Manual -- the identical bucket with removal_policy=DESTROY and NO auto_delete_objects. Nothing
            empties it, so a non-empty bucket makes its own delete fail.

The inline custom-resource context flag keeps the auto-delete handler's code as a template-inline
ZipFile instead of a published asset, so this app needs no `cdk bootstrap`.

Context:
  stack_name -- the stack id
  account    -- the stack's target account
  region     -- the stack's target region
"""
import aws_cdk as cdk
from aws_cdk import aws_s3 as s3


class S3AutoDeleteStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        auto = s3.Bucket(
            self,
            "Auto",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        manual = s3.Bucket(
            self,
            "Manual",
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.CfnOutput(self, "AutoBucketName", value=auto.bucket_name)
        cdk.CfnOutput(self, "ManualBucketName", value=manual.bucket_name)


app = cdk.App()
S3AutoDeleteStack(
    app,
    app.node.try_get_context("stack_name") or "CdkS3AutoDeleteStack",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
