#!/usr/bin/env python3
"""Asset-free CDK app: a state machine with one DynamoPutItem task writing into its own table.

The task's `item` copies `pk` and `marker` from the execution input via JSON paths, so the write
this check reads back is the one the execution actually performed, not a literal baked in.

Context:
  stack_name -- the stack id
  qualifier -- the per-run bootstrap qualifier
  account, region -- the deploy environment
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks


class DynamoPutStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        table = ddb.TableV2(
            self,
            "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            billing=ddb.Billing.on_demand(),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        write = tasks.DynamoPutItem(
            self,
            "WriteItem",
            table=table,
            item={
                "pk": tasks.DynamoAttributeValue.from_string(sfn.JsonPath.string_at("$.pk")),
                "marker": tasks.DynamoAttributeValue.from_string(
                    sfn.JsonPath.string_at("$.marker")
                ),
            },
        )
        machine = sfn.StateMachine(
            self, "Machine", definition_body=sfn.DefinitionBody.from_chainable(write)
        )
        cdk.CfnOutput(self, "StateMachineArn", value=machine.state_machine_arn)
        cdk.CfnOutput(self, "TableName", value=table.table_name)
        cdk.CfnOutput(self, "RoleArn", value=machine.role.role_arn)


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
if not qualifier:
    raise ValueError("context `qualifier` is required")
DynamoPutStack(
    app,
    app.node.try_get_context("stack_name") or "DynamoPutStack",
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
