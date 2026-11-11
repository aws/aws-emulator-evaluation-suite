#!/usr/bin/env python3
"""Asset-free CDK app: a LambdaRestApi whose CloudWatch-role behaviour is feature-flag governed.

`cdk.json` here deliberately carries NO context block, so the flag can be supplied per-synth with
`--context @aws-cdk/aws-apigateway:disableCloudWatchRole=<bool>` and the check can compare the two
templates the SAME app produces.

With the flag false/absent (the legacy default) the RestApi L2 adds an `AWS::ApiGateway::Account`
resource and an IAM role for it. `AWS::ApiGateway::Account` is **account-and-region global**: it sets
one CloudWatch role ARN for every REST API in the account. That is why the deploy arm of the check
runs only with the flag TRUE, and asserts the account-global setting is untouched.

Context:
  stack_name -- the stack id
  marker     -- the string the handler returns in its HTTP body
"""
import aws_cdk as cdk
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_lambda as _lambda

HANDLER = """
import json
import os


def handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"marker": os.environ["MARKER"],
                                "path": event.get("path"),
                                "method": event.get("httpMethod")})}
"""


class RestApiFlagStack(cdk.Stack):
    def __init__(self, scope, construct_id, marker, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        fn = _lambda.Function(
            self,
            "Fn",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER),
            timeout=cdk.Duration.seconds(30),
            environment={"MARKER": marker},
        )
        api = apigw.LambdaRestApi(self, "Api", handler=fn)
        cdk.CfnOutput(self, "RestApiId", value=api.rest_api_id)
        cdk.CfnOutput(self, "InvokeUrl", value=api.url)


app = cdk.App()
RestApiFlagStack(
    app,
    app.node.try_get_context("stack_name") or "CdkRestApiFlagStack",
    marker=app.node.try_get_context("marker") or "unset-marker",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
