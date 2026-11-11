"""cdk-vpc-from-lookup - resolve an existing VPC by tag at SYNTH time and pin its real ids.

VPC_TAG_VALUE is supplied by the check and is matched against the `sim2real` tag. The positive
arm passes the tag value of a VPC the check just deployed with the sibling
deployments/cdk-vpc-l2-defaults app; the negative arm passes a value no VPC carries, which must
fail synthesis. The tag key is `sim2real` rather than `Name` because `ec2.Vpc` writes the
construct path into `Name` (e.g. "<stack>/V"), which is not unique across concurrent runs,
whereas the check controls the `sim2real` value directly through CHECK_ID.
A SecurityGroup is declared so the looked-up vpc_id has to appear as a literal in the
template rather than as a Ref, and select_subnets(PRIVATE_WITH_EGRESS) forces CDK to have
classified the NAT-backed private subnets, not merely to have listed the VPC.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class LookupStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc.from_lookup(self, "V", tags={"sim2real": os.environ["VPC_TAG_VALUE"]})
        sg = ec2.SecurityGroup(self, "SG", vpc=vpc, allow_all_outbound=False,
                               description="sim2real cdk vpc lookup probe")
        egress = vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        public = vpc.select_subnets(subnet_type=ec2.SubnetType.PUBLIC)
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "SgId", value=sg.security_group_id)
        cdk.CfnOutput(self, "EgressSubnetIds", value=",".join(sorted(egress.subnet_ids)))
        cdk.CfnOutput(self, "PublicSubnetIds", value=",".join(sorted(public.subnet_ids)))
        cdk.CfnOutput(self, "EgressAzs", value=",".join(sorted(egress.availability_zones)))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
LookupStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
