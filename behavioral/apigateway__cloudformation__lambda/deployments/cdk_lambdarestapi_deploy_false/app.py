#!/usr/bin/env python3
"""A LambdaRestApi built with deploy=False: the L2 wires the integration and the proxy methods
but creates no Deployment and no Stage.

Context:
  stack_name, function_name, marker -- identify the resources this check created
"""
import aws_cdk as cdk
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_lambda as _lambda

app = cdk.App()
stack_name = app.node.try_get_context("stack_name")
fn_name = app.node.try_get_context("function_name")
marker = app.node.try_get_context("marker")

stack = cdk.Stack(app, stack_name, stack_name=stack_name)

code = (
    "import json\n"
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'body': json.dumps({'marker': '" + marker + "'})}\n"
)
fn = _lambda.Function(
    stack, "Fn", function_name=fn_name, runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler", code=_lambda.Code.from_inline(code),
)
api = apigateway.LambdaRestApi(stack, "Api", handler=fn, deploy=False)

cdk.CfnOutput(stack, "RestApiId", value=api.rest_api_id)
cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)
app.synth()
