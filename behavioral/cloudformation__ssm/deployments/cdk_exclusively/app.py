#!/usr/bin/env python3
"""Asset-free CDK app: Dependent imports Base's parameter value via an automatic CDK
cross-stack reference (Fn::ImportValue), which also makes Dependent depend on Base.

Context:
  account, region           -- the environment
  stack_prefix                -- stack id prefix; stacks are "<prefix>-base"/"<prefix>-dependent"
  param_base, param_dependent -- physical Name of each stack's parameter
  value_base                  -- Value of Base's parameter (the exported value)
"""
import aws_cdk as cdk
from aws_cdk import aws_ssm as ssm


class BaseStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, param_name, value, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.param = ssm.StringParameter(
            self, "Param", parameter_name=param_name, string_value=value,
        )


class DependentStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, param_name, base_param, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        ssm.StringParameter(
            self, "Param", parameter_name=param_name, string_value=base_param.string_value,
        )


app = cdk.App()
prefix = app.node.try_get_context("stack_prefix")
env = cdk.Environment(
    account=app.node.try_get_context("account"),
    region=app.node.try_get_context("region"),
)

base = BaseStack(
    app, f"{prefix}-base",
    param_name=app.node.try_get_context("param_base"),
    value=app.node.try_get_context("value_base"),
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)
DependentStack(
    app, f"{prefix}-dependent",
    param_name=app.node.try_get_context("param_dependent"),
    base_param=base.param,
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=env,
)

app.synth()
