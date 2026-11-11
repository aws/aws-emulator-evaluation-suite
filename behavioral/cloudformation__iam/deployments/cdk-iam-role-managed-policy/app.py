"""cdk-iam-role-managed-policy - an IAM Role with an attached AWS-managed ManagedPolicy."""
import os

import aws_cdk as cdk
from aws_cdk import aws_iam as iam


class RoleManagedPolicyStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        role = iam.Role(
            self, "Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"),
            ],
        )
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])
        cdk.CfnOutput(self, "RoleName", value=role.role_name)
        cdk.CfnOutput(self, "RoleArn", value=role.role_arn)


app = cdk.App()
RoleManagedPolicyStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"],
    ),
)
app.synth()
