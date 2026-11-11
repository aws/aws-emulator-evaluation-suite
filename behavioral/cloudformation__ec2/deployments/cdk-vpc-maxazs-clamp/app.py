"""cdk-vpc-maxazs-clamp - max_azs deliberately larger than any region offers.

MAX_AZS comes from the environment so the check can synthesize the same app at a value it
derives from the live account rather than a literal baked in here. nat_gateways=1 keeps the
cost of a wide VPC to one NAT while leaving the subnet fan-out - the graded property - intact.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class VpcClampStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(self, "V", ip_addresses=ec2.IpAddresses.cidr("10.66.0.0/16"),
                      max_azs=int(os.environ["MAX_AZS"]), nat_gateways=1)
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "AzCount", value=str(len(vpc.availability_zones)))
        cdk.CfnOutput(self, "PublicSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.public_subnets]))
        cdk.CfnOutput(self, "PrivateSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.private_subnets]))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
VpcClampStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
