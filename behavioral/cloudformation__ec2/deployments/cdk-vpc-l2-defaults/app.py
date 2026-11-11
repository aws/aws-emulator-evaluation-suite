"""cdk-vpc-l2-defaults - ec2.Vpc(max_azs=2) with every NAT/subnet default left alone."""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class VpcDefaultsStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(self, "V", ip_addresses=ec2.IpAddresses.cidr("10.63.0.0/16"), max_azs=2)
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "PublicSubnetIds", value=cdk.Fn.join(",", [s.subnet_id for s in vpc.public_subnets]))
        cdk.CfnOutput(self, "PrivateSubnetIds", value=cdk.Fn.join(",", [s.subnet_id for s in vpc.private_subnets]))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
VpcDefaultsStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
