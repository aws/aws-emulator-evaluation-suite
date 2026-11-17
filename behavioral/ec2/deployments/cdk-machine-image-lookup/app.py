"""cdk-machine-image-lookup - MachineImage.lookup by owner and filters, no construct beyond
the resolved image id.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class AmiStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        img = ec2.MachineImage.lookup(
            name=os.environ["AMI_NAME_PATTERN"],
            owners=["amazon"],
            filters={"state": ["available"], "virtualization-type": ["hvm"]},
        )
        resolved = img.get_image(self)
        cdk.CfnOutput(self, "ImageId", value=resolved.image_id)


app = cdk.App()
AmiStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
