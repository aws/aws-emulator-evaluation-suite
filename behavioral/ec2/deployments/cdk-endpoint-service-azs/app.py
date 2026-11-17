"""cdk-endpoint-service-azs - an interface endpoint whose subnets are filtered to the AZs
SERVICE_NAME is published in, via lookup_supported_azs.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class EpStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc.from_lookup(self, "Vpc", is_default=True)
        ec2.InterfaceVpcEndpoint(
            self, "Ep", vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(os.environ["SERVICE_NAME"], 443),
            lookup_supported_azs=True,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )


app = cdk.App()
EpStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
