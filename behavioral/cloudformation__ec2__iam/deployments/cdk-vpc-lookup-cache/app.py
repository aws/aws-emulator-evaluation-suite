"""cdk-vpc-lookup-cache - resolve a tagged VPC via ec2.Vpc.from_lookup once, at synth time.

VPC_TAG_VALUE is matched against the `sim2real` tag the check puts on the VPC it creates with
boto3. A SecurityGroup is declared so the resolved vpc_id reaches the template as a literal
rather than a Ref, which is what proves a lookup actually resolved rather than merely ran.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2


class LookupStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc.from_lookup(self, "V", tags={"sim2real": os.environ["VPC_TAG_VALUE"]})
        sg = ec2.SecurityGroup(self, "SG", vpc=vpc, allow_all_outbound=False,
                               description="sim2real cdk vpc lookup cache probe")
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "SgId", value=sg.security_group_id)


app = cdk.App()
LookupStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
