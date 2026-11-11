#!/usr/bin/env python3
"""CDK app whose Lambda Function Environment.Variables is driven by context.

Uses the L1 `CfnFunction` for the function (rather than the L2 `Function`), because the L2
construct's `addEnvironment` rejects a Lambda-reserved variable name at synth time -- the
rejection this app exists to trigger must come from AWS at deploy time, not from the CDK
toolkit itself.

Context:
  stack_name -- the stack id
  marker     -- value of the MARKER environment variable
  bad        -- "1" adds AWS_REGION (a Lambda-reserved key) to Environment.Variables
"""
import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda

app = cdk.App()
marker = app.node.try_get_context("marker")
bad = app.node.try_get_context("bad") == "1"


class RollbackStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        role = iam.Role(
            self, "Role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"),
            ],
        )
        variables = {"MARKER": marker}
        if bad:
            variables["AWS_REGION"] = "us-east-1"
        fn = _lambda.CfnFunction(
            self, "Fn",
            runtime="python3.12",
            handler="index.handler",
            role=role.role_arn,
            code=_lambda.CfnFunction.CodeProperty(
                zip_file="def handler(event, context):\n    return {}\n"),
            environment=_lambda.CfnFunction.EnvironmentProperty(variables=variables),
            timeout=30,
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.ref)


RollbackStack(
    app, app.node.try_get_context("stack_name"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
