#!/usr/bin/env python3
"""Asset-free CDK app: a RestApi whose route set is context-driven.

  routes=one -- `GET /a` only.
  routes=two -- `GET /a` and `GET /b`.

`RestApi` auto-creates one `AWS::ApiGateway::Deployment` whose LOGICAL ID carries a suffix derived
from the API's configuration, precisely so that adding a method mints a NEW Deployment resource and
the stage is repointed at it. A template that reuses one Deployment logical id across a method change
deploys cleanly and then serves 403 on the new route forever — the classic hand-written-CloudFormation
API Gateway bug. This app exists to make that difference observable over real HTTPS.

Explicit `RestApi` + `add_resource`/`add_method` rather than `LambdaRestApi`, because
`LambdaRestApi`'s default `{proxy+}`/ANY route would answer BOTH paths and there would be nothing to
detect.

Context:
  stack_name -- the stack id
  routes     -- "one" | "two"
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
            "body": json.dumps({"marker": os.environ["MARKER"], "path": event.get("path")})}
"""


class RestApiRedeployStack(cdk.Stack):
    def __init__(self, scope, construct_id, routes, marker, **kwargs):
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
        api = apigw.RestApi(self, "Api")
        integration = apigw.LambdaIntegration(fn)
        for path in routes:
            api.root.add_resource(path).add_method("GET", integration)

        cdk.CfnOutput(self, "RestApiId", value=api.rest_api_id)
        cdk.CfnOutput(self, "InvokeUrl", value=api.url)
        cdk.CfnOutput(self, "RouteCount", value=str(len(routes)))


app = cdk.App()
_ROUTE_SETS = {"one": ["a"], "two": ["a", "b"]}
requested = app.node.try_get_context("routes")
if requested not in _ROUTE_SETS:
    raise ValueError(f"context `routes` must be one of {sorted(_ROUTE_SETS)}, got {requested!r}")

RestApiRedeployStack(
    app,
    app.node.try_get_context("stack_name") or "CdkRestApiRedeployStack",
    routes=_ROUTE_SETS[requested],
    marker=app.node.try_get_context("marker") or "unset-marker",
    synthesizer=cdk.LegacyStackSynthesizer(),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
