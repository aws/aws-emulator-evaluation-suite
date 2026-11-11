import os

import aws_cdk as cdk
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy


class BucketDeploymentStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        dest = s3.Bucket.from_bucket_name(self, "Dest", os.environ["DEST_BUCKET"])
        s3deploy.BucketDeployment(
            self, "Deploy",
            sources=[s3deploy.Source.asset(os.environ["SOURCE_DIR"])],
            destination_bucket=dest,
        )


app = cdk.App()
BucketDeploymentStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
