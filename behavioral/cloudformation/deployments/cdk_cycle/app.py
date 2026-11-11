#!/usr/bin/env python3
"""Asset-free CDK app with three context-selected shapes, for the two-layer cycle check.

  mode=valid           -- Two stacks. `Data` owns a Table; `Compute` owns a Function that references
                          the Table by name. One direction only, so it synthesises and deploys.

  mode=construct-cycle -- The same two stacks, plus an Output on `Data` that references something in
                          `Compute`. CDK refuses this at SYNTH TIME, in the library, before any
                          template exists: `DependencyCycle: 'Data' depends on 'Compute' (...).
                          Adding this dependency (...) would create a cyclic reference.`

  mode=template-cycle  -- ONE stack holding two raw `CfnResource`s (SSM parameters) whose Values
                          each `Fn::GetAtt` the other. CDK synthesises this HAPPILY — it inspects the
                          construct graph, not the `Fn::GetAtt` graph of escape-hatch resources — and
                          the resulting template is refused by CloudFormation itself.

The pair of negatives is the subject: CDK's synth-time validation is NOT a superset of
CloudFormation's, so a template CDK will emit can still be rejected by the target.

Context:
  stack_name -- the stack id PREFIX; the two-stack modes append `-data` / `-compute`
  mode       -- "valid" | "construct-cycle" | "template-cycle"
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import os

import boto3

ddb = boto3.client("dynamodb")


def handler(event, context):
    ddb.put_item(TableName=os.environ["TABLE"],
                 Item={"pk": {"S": event["key"]}, "marker": {"S": event["marker"]}})
    return {"wrote": event["key"], "table": os.environ["TABLE"]}
"""


class DataStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.table = ddb.Table(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        cdk.CfnOutput(self, "TableName", value=self.table.table_name)


class ComputeStack(cdk.Stack):
    def __init__(self, scope, construct_id, table, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER),
            timeout=cdk.Duration.seconds(30),
            environment={"TABLE": table.table_name},
        )
        table.grant_read_write_data(self.fn)
        cdk.CfnOutput(self, "FunctionName", value=self.fn.function_name)


class TemplateCycleStack(cdk.Stack):
    """Two escape-hatch resources whose Values cross-reference by Fn::GetAtt.

    Written with `CfnResource` on purpose: an L2 pair would make CDK's construct-graph checker see
    the cycle and refuse it at synth, which is the OTHER arm. Here the cycle exists only in the
    emitted template, so the refusal has to come from the target.
    """

    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        left = cdk.CfnResource(
            self,
            "Left",
            type="AWS::SSM::Parameter",
            properties={"Type": "String", "Value": "seed"},
        )
        right = cdk.CfnResource(
            self,
            "Right",
            type="AWS::SSM::Parameter",
            properties={"Type": "String", "Value": left.get_att("Value").to_string()},
        )
        left.add_property_override("Value", right.get_att("Value").to_string())


app = cdk.App()
mode = app.node.try_get_context("mode")
prefix = app.node.try_get_context("stack_name") or "CdkCycleStack"
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region"),
)

if mode == "template-cycle":
    TemplateCycleStack(app, prefix, synthesizer=cdk.LegacyStackSynthesizer(), env=env)
elif mode in ("valid", "construct-cycle"):
    data = DataStack(app, f"{prefix}-data", synthesizer=cdk.LegacyStackSynthesizer(), env=env)
    compute = ComputeStack(
        app, f"{prefix}-compute", table=data.table,
        synthesizer=cdk.LegacyStackSynthesizer(), env=env,
    )
    if mode == "construct-cycle":
        cdk.CfnOutput(data, "PeerFunctionName", value=compute.fn.function_name)
else:
    raise ValueError(
        f"context `mode` must be 'valid', 'construct-cycle' or 'template-cycle', got {mode!r}"
    )

app.synth()
