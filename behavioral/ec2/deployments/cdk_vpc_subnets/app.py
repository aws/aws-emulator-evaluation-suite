#!/usr/bin/env python3
"""Asset-free CDK app: one VPC with a PUBLIC and a PRIVATE_ISOLATED subnet group across 2 AZs.

`LegacyStackSynthesizer` on purpose: it leaves `stackTemplateAssetObjectUrl` unset, so the template
can be handed to CloudFormation directly (inline TemplateBody) with no asset bucket and no
`cdk bootstrap`.

Context:
  stack_name -- the CDK construct id (not the CloudFormation stack name the check creates)
"""
import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class VpcSubnetsStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, synthesizer=cdk.LegacyStackSynthesizer(), **kwargs)
        vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.86.0.0/16"),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="Public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24),
                ec2.SubnetConfiguration(
                    name="Isolated", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=24
                ),
            ],
        )
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "PublicSubnetIds", value=",".join(s.subnet_id for s in vpc.public_subnets))
        cdk.CfnOutput(
            self, "IsolatedSubnetIds", value=",".join(s.subnet_id for s in vpc.isolated_subnets)
        )


app = cdk.App()
VpcSubnetsStack(app, app.node.try_get_context("stack_name") or "VpcSubnetsStack")
app.synth()
