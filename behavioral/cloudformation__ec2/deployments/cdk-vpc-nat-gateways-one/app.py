"""cdk-vpc-nat-gateways-one - identical to cdk-vpc-l2-defaults except nat_gateways=1.

The twin control for the per-AZ NAT default: same max_azs, same CIDR shape, one property
changed. Both private subnets must therefore egress through the SAME single NAT gateway.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class VpcOneNatStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(self, "V", ip_addresses=ec2.IpAddresses.cidr("10.64.0.0/16"),
                      max_azs=2, nat_gateways=1)
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "PublicSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.public_subnets]))
        cdk.CfnOutput(self, "PrivateSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.private_subnets]))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
VpcOneNatStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
