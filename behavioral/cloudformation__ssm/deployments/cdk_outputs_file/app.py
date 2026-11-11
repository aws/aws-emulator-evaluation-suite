#!/usr/bin/env python3
"""Asset-free CDK app: two independent stacks, each with two CfnOutputs on an SSM parameter.

Context:
  account, region   -- the environment
  stack_a, stack_b  -- stack ids
  param_a, param_b  -- physical Name of each stack's parameter
  value_a, value_b  -- Value of each stack's parameter
"""
import aws_cdk as cdk
from aws_cdk import aws_ssm as ssm


class ParamStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, param_name, value, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        param = ssm.StringParameter(
            self, "Param", parameter_name=param_name, string_value=value,
        )
        cdk.CfnOutput(self, "ParamArn", value=param.parameter_arn)
        cdk.CfnOutput(self, "ParamValue", value=param.string_value)


app = cdk.App()
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region"),
)

ParamStack(
    app, app.node.try_get_context("stack_a"),
    param_name=app.node.try_get_context("param_a"),
    value=app.node.try_get_context("value_a"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)
ParamStack(
    app, app.node.try_get_context("stack_b"),
    param_name=app.node.try_get_context("param_b"),
    value=app.node.try_get_context("value_b"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)

app.synth()
