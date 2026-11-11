import os

import aws_cdk as cdk
from aws_cdk import aws_ssm as ssm
from aws_cdk import custom_resources as cr


class LifecycleStack(cdk.Stack):
    """A Custom::AWS resource that writes an SSM parameter; its response field feeds a sibling."""

    def __init__(self, scope, sid, *, param_name: str, value: str, mirror_name: str, **kw):
        super().__init__(scope, sid, **kw)
        param_arn = self.format_arn(service="ssm", resource="parameter", resource_name=param_name)
        put_call = cr.AwsSdkCall(
            service="SSM",
            action="putParameter",
            parameters={"Name": param_name, "Value": value, "Type": "String", "Overwrite": True},
            physical_resource_id=cr.PhysicalResourceId.of(param_name),
            output_paths=["Version"],
        )
        writer = cr.AwsCustomResource(
            self, "Writer",
            on_create=put_call,
            on_update=put_call,
            on_delete=cr.AwsSdkCall(
                service="SSM",
                action="deleteParameter",
                parameters={"Name": param_name},
                ignore_error_codes_matching="ParameterNotFound",
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(resources=[param_arn]),
            install_latest_aws_sdk=False,
        )
        ssm.CfnParameter(
            self, "Mirror",
            name=mirror_name,
            type="String",
            value=writer.get_response_field("Version"),
        )


class ConflictStack(cdk.Stack):
    """A Custom::AWS onCreate call that AWS itself refuses; no IAM grant is at fault."""

    def __init__(self, scope, sid, *, param_name: str, value: str, **kw):
        super().__init__(scope, sid, **kw)
        param_arn = self.format_arn(service="ssm", resource="parameter", resource_name=param_name)
        cr.AwsCustomResource(
            self, "Writer",
            on_create=cr.AwsSdkCall(
                service="SSM",
                action="putParameter",
                parameters={"Name": param_name, "Value": value, "Type": "String"},
                physical_resource_id=cr.PhysicalResourceId.of(param_name),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(resources=[param_arn]),
            install_latest_aws_sdk=False,
        )


app = cdk.App()
env = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])
synthesizer = cdk.DefaultStackSynthesizer(qualifier=os.environ["QUALIFIER"])
scenario = os.environ["SCENARIO"]
if scenario == "lifecycle":
    LifecycleStack(
        app, os.environ["STACK_NAME"], env=env, synthesizer=synthesizer,
        param_name=os.environ["PARAM_NAME"],
        value=os.environ["PARAM_VALUE"],
        mirror_name=os.environ["MIRROR_NAME"],
    )
elif scenario == "conflict":
    ConflictStack(
        app, os.environ["STACK_NAME"], env=env, synthesizer=synthesizer,
        param_name=os.environ["CONFLICT_PARAM_NAME"],
        value=os.environ["CONFLICT_VALUE"],
    )
else:
    raise ValueError(f"unknown SCENARIO {scenario!r}")
app.synth()
