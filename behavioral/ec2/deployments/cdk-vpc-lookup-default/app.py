"""cdk-vpc-lookup-default - Vpc.from_lookup(is_default=True), returning VPN gateways too.

No resource is declared; the stack's only content is the lookup's resolved VpcId and CIDR.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class LookupStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc.from_lookup(self, "Vpc", is_default=True, return_vpn_gateways=True)
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "VpcCidr", value=vpc.vpc_cidr_block)


app = cdk.App()
LookupStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
