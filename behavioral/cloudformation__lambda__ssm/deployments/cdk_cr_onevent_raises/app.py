#!/usr/bin/env python3
"""CDK app: a custom_resources.Provider-backed custom resource whose onEvent handler raises on
Create when told to, and otherwise writes the SSM parameter it manages.

Context:
  stack_name -- the stack id
  qualifier  -- bootstrap qualifier the stack is synthesized against
  account, region -- the environment to synthesize for
  marker     -- value the handler writes to the parameter, and embeds in its raised error
  param_name -- the SSM parameter name the custom resource manages
  force_fail -- "true" | "false": whether Create raises before writing the parameter
"""
import aws_cdk as cdk
from aws_cdk import CustomResource
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import custom_resources as cr

_HANDLER = '''
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    props = event["ResourceProperties"]
    marker = props["Marker"]
    param_name = props["ParamName"]
    ssm = boto3.client("ssm")
    request_type = event["RequestType"]
    if request_type == "Create":
        if props.get("ForceFail") == "true":
            raise Exception(f"sim2real-onevent-failure-{marker}")
        ssm.put_parameter(Name=param_name, Value=marker, Type="String")
    elif request_type == "Delete":
        try:
            ssm.delete_parameter(Name=param_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
    return {"PhysicalResourceId": param_name}
'''


class ProviderRaisesStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        marker = self.node.try_get_context("marker")
        param_name = self.node.try_get_context("param_name")
        force_fail = self.node.try_get_context("force_fail")

        on_event = _lambda.Function(
            self, "OnEvent",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(_HANDLER),
            timeout=cdk.Duration.seconds(30),
        )
        on_event.add_to_role_policy(iam.PolicyStatement(
            actions=["ssm:PutParameter", "ssm:DeleteParameter"],
            resources=[self.format_arn(service="ssm", resource="parameter",
                                       resource_name=param_name.lstrip("/"))],
        ))

        provider = cr.Provider(self, "Provider", on_event_handler=on_event)
        CustomResource(
            self, "Widget",
            service_token=provider.service_token,
            properties={"Marker": marker, "ParamName": param_name, "ForceFail": force_fail},
        )


app = cdk.App()
ProviderRaisesStack(
    app, app.node.try_get_context("stack_name"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=app.node.try_get_context("qualifier")),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
