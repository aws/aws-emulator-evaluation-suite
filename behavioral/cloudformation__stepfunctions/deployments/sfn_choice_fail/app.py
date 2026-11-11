#!/usr/bin/env python3
"""Asset-free CDK app: one state machine with a Choice into a Fail state.

Context:
  stack_name -- the stack id
  qualifier -- the per-run bootstrap qualifier
  account, region -- the deploy environment
"""
import aws_cdk as cdk
from aws_cdk import aws_stepfunctions as sfn


class ChoiceFailStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        done = sfn.Succeed(self, "Done")
        rejected = sfn.Fail(
            self,
            "Rejected",
            error="ValidationFailed",
            cause="input failed the required shouldFail validation check",
        )
        choice = sfn.Choice(self, "CheckFlag")
        choice.when(sfn.Condition.boolean_equals("$.shouldFail", True), rejected)
        choice.otherwise(done)

        machine = sfn.StateMachine(
            self,
            "Machine",
            definition_body=sfn.DefinitionBody.from_chainable(choice),
        )
        cdk.CfnOutput(self, "StateMachineArn", value=machine.state_machine_arn)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
if not qualifier:
    raise ValueError("context `qualifier` is required")
ChoiceFailStack(
    app,
    app.node.try_get_context("stack_name") or "ChoiceFailStack",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
