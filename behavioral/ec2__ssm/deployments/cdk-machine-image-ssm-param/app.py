"""cdk-machine-image-ssm-param - MachineImage.from_ssm_parameter with cached_in_context=True,
which resolves the parameter at synth time instead of emitting a deploy-time dynamic reference.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class SsmAmiStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        img = ec2.MachineImage.from_ssm_parameter(
            os.environ["PARAM_NAME"], cached_in_context=True)
        resolved = img.get_image(self)
        cdk.CfnOutput(self, "ImageId", value=resolved.image_id)


app = cdk.App()
SsmAmiStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
