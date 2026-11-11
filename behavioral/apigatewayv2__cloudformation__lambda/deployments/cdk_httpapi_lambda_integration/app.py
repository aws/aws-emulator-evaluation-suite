#!/usr/bin/env python3
"""An HttpApi whose default route proxies to a Lambda function.

Context:
  stack_name, function_name, marker -- identify the resources this check created
"""
import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_lambda as _lambda
from aws_cdk.aws_apigatewayv2_authorizers import HttpIamAuthorizer
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration

app = cdk.App()
stack_name = app.node.try_get_context("stack_name")
fn_name = app.node.try_get_context("function_name")
marker = app.node.try_get_context("marker")

stack = cdk.Stack(app, stack_name, stack_name=stack_name)

code = (
    "import json\n"
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'headers': {'content-type': 'application/json'},\n"
    "            'body': json.dumps({'marker': '" + marker + "'})}\n"
)
fn = _lambda.Function(
    stack, "Fn", function_name=fn_name, runtime=_lambda.Runtime.PYTHON_3_12,
    handler="index.handler", code=_lambda.Code.from_inline(code),
)
api = apigwv2.HttpApi(
    stack, "Api", api_name=stack_name,
    default_integration=HttpLambdaIntegration("Integ", fn),
    # Every route requires SigV4, so the default stage is never anonymously invokable.
    default_authorizer=HttpIamAuthorizer(),
)

cdk.CfnOutput(stack, "ApiId", value=api.api_id)
cdk.CfnOutput(stack, "ApiEndpoint", value=api.api_endpoint)
cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)
app.synth()
