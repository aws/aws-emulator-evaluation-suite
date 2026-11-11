#!/usr/bin/env python3
"""Asset-free CDK app: three Functions that differ ONLY in how their logging is provisioned.

  Plain     -- nothing but the three required props. The L2 mints an execution role with exactly one
               managed policy (`service-role/AWSLambdaBasicExecutionRole`) and NO log group, so
               Lambda creates `/aws/lambda/<name>` on first invoke with no expiry.
  Retained  -- the same Function with an explicit LogGroup at ONE_DAY, the twin control group that
               proves the default's "never expire" is a decision and not an absence of plumbing.
  Deprived  -- the same Function with an explicit role that trusts lambda.amazonaws.com and carries
               NO policy at all. It still RUNS (Lambda does not need logs permissions to execute),
               but it can never write a log event. This is the negative arm's subject; the check
               repairs it by attaching the managed policy and demands the logs appear.

`log_retention=` is deliberately NOT used: that property emits a
`Custom::LogRetention` provider Lambda whose code is a bundled ASSET, which would drag this app onto
the bootstrap path. `log_group=` produces `LoggingConfig.LogGroup` with no asset.

Context:
  stack_name -- the stack id
"""
import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs

HANDLER = """
import os


def handler(event, context):
    # Printed to stdout, which is the ONLY way this code can reach CloudWatch Logs, so the marker's
    # presence in the log group is a statement about the execution role and nothing else.
    print("SIM2REAL-LOG-MARKER " + event["marker"])
    return {"echoed": event["marker"], "fn": os.environ.get("AWS_LAMBDA_FUNCTION_NAME")}
"""


class FnDefaultsStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        common = {
            "runtime": _lambda.Runtime.PYTHON_3_12,
            "handler": "index.handler",
            "code": _lambda.Code.from_inline(HANDLER),
            "timeout": cdk.Duration.seconds(30),
        }

        # NOT named "Default": CDK ELIDES the construct ids `Default` and `Resource` from the
        # logical-id path, so a Function with id "Default" synthesises to logical id
        # `Resource`, which is unreadable in stack events.
        plain_fn = _lambda.Function(self, "Plain", **common)

        retained_group = logs.LogGroup(
            self,
            "RetainedLogs",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        retained_fn = _lambda.Function(self, "Retained", log_group=retained_group, **common)

        deprived_role = iam.Role(
            self,
            "DeprivedRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        deprived_fn = _lambda.Function(self, "Deprived", role=deprived_role, **common)

        # `fn.role` is the role the L2 minted. Exported so the check reads the real role name off
        # the stack instead of reconstructing CDK's logical-id hash, which is version-dependent.
        assert plain_fn.role is not None, "the Function L2 always mints an execution role"
        cdk.CfnOutput(self, "PlainRoleName", value=plain_fn.role.role_name)
        cdk.CfnOutput(self, "PlainFunctionName", value=plain_fn.function_name)
        cdk.CfnOutput(self, "RetainedFunctionName", value=retained_fn.function_name)
        cdk.CfnOutput(self, "RetainedLogGroupName", value=retained_group.log_group_name)
        cdk.CfnOutput(self, "DeprivedFunctionName", value=deprived_fn.function_name)
        cdk.CfnOutput(self, "DeprivedRoleName", value=deprived_role.role_name)


app = cdk.App()
FnDefaultsStack(
    app,
    app.node.try_get_context("stack_name") or "CdkFnDefaultsStack",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
