#!/usr/bin/env python3
"""Asset-free CDK app: one S3 bucket that sets only `block_public_acls` on its BlockPublicAccess.

`cdk.json` carries no context block, so `@aws-cdk/aws-s3:publicAccessBlockedByDefault` is supplied
per-synth with `--context`, and the check compares the two templates (and the two deployed
buckets) the same app produces.

Context:
  stack_name -- the stack id
"""
import aws_cdk as cdk
from aws_cdk import aws_s3 as s3


class S3PublicAccessBlockFlagStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        bucket = s3.Bucket(
            self,
            "B",
            block_public_access=s3.BlockPublicAccess(block_public_acls=True),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.CfnOutput(self, "BucketName", value=bucket.bucket_name)


app = cdk.App()
S3PublicAccessBlockFlagStack(
    app,
    app.node.try_get_context("stack_name") or "CdkS3PublicAccessBlockFlagStack",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
