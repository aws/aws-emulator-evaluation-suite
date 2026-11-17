"""cdk-availability-zones - a stack with a specified env reads Stack.availability_zones."""
import os

import aws_cdk as cdk


class AzStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        cdk.CfnOutput(self, "Azs", value=",".join(self.availability_zones))


app = cdk.App()
AzStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
