#!/usr/bin/env python3
"""Asset-free CDK app: three stacks. Dependent explicitly depends on Base; Independent does not.

Context:
  account, region                       -- the environment
  stack_base, stack_dependent, stack_independent -- stack ids
  param_base, param_dependent, param_independent -- physical Name of each stack's parameter
  value_base, value_dependent, value_independent -- Value of each stack's parameter
"""
import aws_cdk as cdk
from aws_cdk import aws_ssm as ssm


class ParamStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, param_name, value, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        ssm.StringParameter(self, "Param", parameter_name=param_name, string_value=value)


app = cdk.App()
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region"),
)

base = ParamStack(
    app, app.node.try_get_context("stack_base"),
    param_name=app.node.try_get_context("param_base"),
    value=app.node.try_get_context("value_base"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)
dependent = ParamStack(
    app, app.node.try_get_context("stack_dependent"),
    param_name=app.node.try_get_context("param_dependent"),
    value=app.node.try_get_context("value_dependent"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)
dependent.add_dependency(base)
ParamStack(
    app, app.node.try_get_context("stack_independent"),
    param_name=app.node.try_get_context("param_independent"),
    value=app.node.try_get_context("value_independent"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)

app.synth()
