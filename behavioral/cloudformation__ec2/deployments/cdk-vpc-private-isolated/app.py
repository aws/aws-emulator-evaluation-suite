"""cdk-vpc-private-isolated - PUBLIC + PRIVATE_ISOLATED subnet_configuration, nat_gateways=0.

The isolated subnets must deploy with NO default route of any kind. The public subnets in the
same stack are the in-file positive control that the stack's route plumbing works at all.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class VpcIsolatedStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(
            self, "V",
            ip_addresses=ec2.IpAddresses.cidr("10.65.0.0/16"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="Pub", subnet_type=ec2.SubnetType.PUBLIC,
                                        cidr_mask=24),
                ec2.SubnetConfiguration(name="Iso",
                                        subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                                        cidr_mask=24),
            ],
        )
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "PublicSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.public_subnets]))
        cdk.CfnOutput(self, "IsolatedSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.isolated_subnets]))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
VpcIsolatedStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
