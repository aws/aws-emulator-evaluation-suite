#!/usr/bin/env python3
"""A parent stack with one NestedStack, whose output the parent re-exposes as its own.

The nested stack owns a single SSM parameter and a ParamName output naming it; the parent has no
resources of its own beyond the nested stack and a CfnOutput that references the parameter, which
CDK resolves through an output it generates on the nested stack.

Context:
  stack_name   -- the parent stack id
  marker_value -- the string the nested parameter is given
  qualifier    -- bootstrap qualifier (the nested template is a file asset)
  account/region -- the CDK environment
"""
import aws_cdk as cdk
from aws_cdk import NestedStack
from aws_cdk import aws_ssm as ssm


class ChildStack(NestedStack):
    def __init__(self, scope, construct_id, *, marker_value, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        param = ssm.StringParameter(self, "Param", string_value=marker_value)
        cdk.CfnOutput(self, "ParamName", value=param.parameter_name)
        self.param_name = param.parameter_name


class ParentStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, marker_value, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        child = ChildStack(self, "Child", marker_value=marker_value)
        cdk.CfnOutput(self, "ChildParamName", value=child.param_name)


app = cdk.App()
ParentStack(
    app,
    app.node.try_get_context("stack_name"),
    marker_value=app.node.try_get_context("marker_value"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=app.node.try_get_context("qualifier")),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
