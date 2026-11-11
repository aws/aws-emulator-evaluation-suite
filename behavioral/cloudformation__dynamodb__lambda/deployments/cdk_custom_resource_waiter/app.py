#!/usr/bin/env python3
"""CDK app: one `custom_resources.Provider` (onEvent + isComplete) behind one CustomResource.

`isComplete` only reports done on its SECOND call for a given request (tracked in a DynamoDB
item keyed by physical-id+request-id), and only ITS Data carries the real `Value` attribute
-- `onEvent` sets `Value` to a placeholder that only isComplete's Data overrides. `onEvent` always computes the same
PhysicalResourceId from the stack id and logical id, independent of the `Seed` property, so an
update that only changes `Seed` must not replace the resource. With `never_complete=true`,
`isComplete` always answers False, so the Provider's waiter must time out the stack rather than
let it settle.

Context:
  stack_name       -- the stack id
  qualifier        -- bootstrap qualifier (DefaultStackSynthesizer; the Provider framework Lambda
                       is a real CDK-library asset, so this app is never asset-free)
  seed             -- the resource property threaded into the isComplete-computed `Value` output
  never_complete   -- "true" makes isComplete always answer False (default "false")
  total_timeout_s  -- the Provider's total_timeout, in seconds (default 180)
"""
import aws_cdk as cdk
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as _lambda
from aws_cdk import custom_resources as cr

ON_EVENT_CODE = """
import os
import boto3

TABLE_NAME = os.environ["TABLE_NAME"]
table = boto3.resource("dynamodb").Table(TABLE_NAME)


def handler(event, context):
    request_type = event["RequestType"]
    print(f"REQUEST_ID={request_type}:{event['RequestId']}")
    stack_id = event["StackId"].split("/")[1]
    physical_id = f"cr-{stack_id}-{event['LogicalResourceId']}"
    if request_type == "Delete":
        return {"PhysicalResourceId": physical_id}
    seed = event.get("ResourceProperties", {}).get("Seed", "")
    pk = f"{physical_id}:{event['RequestId']}"
    table.put_item(Item={"pk": pk, "seed": seed, "attempts": 0})
    return {"PhysicalResourceId": physical_id, "Data": {"Value": "unset-by-on-event"}}
"""

IS_COMPLETE_CODE = """
import os
import boto3

TABLE_NAME = os.environ["TABLE_NAME"]
NEVER_COMPLETE = os.environ["NEVER_COMPLETE"] == "true"
table = boto3.resource("dynamodb").Table(TABLE_NAME)


def handler(event, context):
    if event["RequestType"] == "Delete":
        return {"IsComplete": True}
    if NEVER_COMPLETE:
        return {"IsComplete": False}
    physical_id = event["PhysicalResourceId"]
    pk = f"{physical_id}:{event['RequestId']}"
    updated = table.update_item(
        Key={"pk": pk},
        UpdateExpression="ADD attempts :one",
        ExpressionAttributeValues={":one": 1},
        ReturnValues="UPDATED_NEW",
    )
    attempts = int(updated["Attributes"]["attempts"])
    if attempts < 2:
        return {"IsComplete": False}
    item = table.get_item(Key={"pk": pk}, ConsistentRead=True)["Item"]
    return {"IsComplete": True, "Data": {"Value": f"computed-{item['seed']}"}}
"""


class WaiterStack(cdk.Stack):
    def __init__(self, scope, construct_id, seed: str, never_complete: bool,
                 total_timeout_s: int, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        table = dynamodb.Table(
            self,
            "State",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        on_event = _lambda.Function(
            self,
            "OnEvent",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(ON_EVENT_CODE),
            timeout=cdk.Duration.seconds(30),
            environment={"TABLE_NAME": table.table_name},
        )
        is_complete = _lambda.Function(
            self,
            "IsComplete",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(IS_COMPLETE_CODE),
            timeout=cdk.Duration.seconds(30),
            environment={"TABLE_NAME": table.table_name,
                         "NEVER_COMPLETE": "true" if never_complete else "false"},
        )
        table.grant_read_write_data(on_event)
        table.grant_read_write_data(is_complete)

        provider = cr.Provider(
            self,
            "Provider",
            on_event_handler=on_event,
            is_complete_handler=is_complete,
            query_interval=cdk.Duration.seconds(5),
            total_timeout=cdk.Duration.seconds(total_timeout_s),
        )
        resource = cdk.CustomResource(
            self,
            "Waited",
            service_token=provider.service_token,
            properties={"Seed": seed},
        )
        cdk.CfnOutput(self, "PhysicalId", value=resource.ref)
        cdk.CfnOutput(self, "Value", value=resource.get_att_string("Value"))


app = cdk.App()
qualifier = app.node.try_get_context("qualifier")
if not qualifier:
    raise ValueError("this app requires a `qualifier` context value")

WaiterStack(
    app,
    app.node.try_get_context("stack_name") or "CdkCustomResourceWaiterStack",
    seed=app.node.try_get_context("seed") or "unset-seed",
    never_complete=(app.node.try_get_context("never_complete") == "true"),
    total_timeout_s=int(app.node.try_get_context("total_timeout_s") or "180"),
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier),
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)
app.synth()
