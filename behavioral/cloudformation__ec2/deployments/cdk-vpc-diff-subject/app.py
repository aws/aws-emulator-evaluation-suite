"""cdk-vpc-diff-subject - a VPC carrying one template-visible tag value from the environment.

`cdk diff` compares the LOCALLY synthesized template against the template CloudFormation
holds for the deployed stack. DIFF_MARKER is the one property the check can change locally
without touching AWS, which is how the check separates "cdk diff sees a template change"
from "cdk diff sees a real-resource change" - it does not see the latter at all.
nat_gateways=0 because nothing here needs egress and a NAT would triple the teardown.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class DiffStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(
            self, "V", ip_addresses=ec2.IpAddresses.cidr("10.67.0.0/16"),
            max_azs=2, nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="Pub", subnet_type=ec2.SubnetType.PUBLIC,
                                        cidr_mask=24),
            ],
        )
        cdk.Tags.of(vpc).add("Sim2realDiffMarker", os.environ["DIFF_MARKER"])
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "PublicSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.public_subnets]))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
DiffStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
