"""cdk-construct-validation - one ec2.Vpc whose CIDR comes from the environment.

The check synthesizes this app three times: with a CIDR too small to allocate the declared
/24 subnets, with a string that is not an IP address at all, and with a valid twin that
differs in nothing else. No branch lives here - the only difference between the runs is the
value of VPC_CIDR.

Synthesized offline against aws-cdk-lib 2.263.0: neither failure names the CDK
CONSTRUCT PATH. They name the CIDR arithmetic ("1 of /24 exceeds remaining space of
<cidr>", under the error class SubnetCountExceedsRemainingSpace) and the bad input
("InvalidIpAddress: <value> is not valid"). An earlier version of this docstring claimed
synth names the construct path; that was measured false and is corrected here.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class CidrStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(self, "Vpc",
                      ip_addresses=ec2.IpAddresses.cidr(os.environ["VPC_CIDR"]),
                      max_azs=2, nat_gateways=0,
                      subnet_configuration=[
                          ec2.SubnetConfiguration(name="Pub",
                                                  subnet_type=ec2.SubnetType.PUBLIC,
                                                  cidr_mask=24),
                      ])
        cdk.CfnOutput(self, "VpcCidr", value=vpc.vpc_cidr_block)
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
CidrStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
