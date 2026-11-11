#!/usr/bin/env python3
"""Asset-free CDK app: a state machine with one LambdaInvoke task, payload-response-only.

The function doubles a number and logs and echoes a tag; `payload_response_only=True` makes the task's
result (and so the whole execution's output, the only state) exactly that return value, with no
Lambda invocation envelope wrapped around it.

Context:
  stack_name -- the stack id
  retry_service_exceptions -- "false" turns off the task's default retry on Lambda errors
  qualifier -- the per-run bootstrap qualifier
  account, region -- the deploy environment
"""
import aws_cdk as cdk
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks

_HANDLER = """
def handler(event, context):
    print("tag", event.get("tag"))
    return {"doubled": event["value"] * 2, "echo": event.get("tag")}
"""


class LambdaInvokeStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, retry_service_exceptions: bool, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        fn = lambda_.Function(
            self,
            "Fn",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline(_HANDLER),
        )
        invoke = tasks.LambdaInvoke(
            self, "InvokeFn", lambda_function=fn, payload_response_only=True,
            retry_on_service_exceptions=retry_service_exceptions,
        )
        machine = sfn.StateMachine(
            self, "Machine", definition_body=sfn.DefinitionBody.from_chainable(invoke)
        )
        cdk.CfnOutput(self, "StateMachineArn", value=machine.state_machine_arn)
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)
        cdk.CfnOutput(self, "RoleArn", value=machine.role.role_arn)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
if not qualifier:
    raise ValueError("context `qualifier` is required")
LambdaInvokeStack(
    app,
    app.node.try_get_context("stack_name") or "LambdaInvokeStack",
    retry_service_exceptions=app.node.try_get_context("retry_service_exceptions") != "false",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
