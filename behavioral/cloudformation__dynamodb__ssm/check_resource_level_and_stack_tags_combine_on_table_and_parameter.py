"""resource-level-and-stack-tags-combine-on-table-and-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-level-and-stack-tags-combine-on-table-and-parameter"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "ssm"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(table_name: str, parameter_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "Tags": [{"Key": "table-resource-tag", "Value": "tv"}],
                },
            },
            "Parameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": parameter_name,
                    "Type": "String",
                    "Value": "sim2real-placeholder",
                    "Tags": {"param-resource-tag": "pv"},
                },
            },
        },
        "Outputs": {"TableArn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource's own Tags property and the stack's Tags combine on that resource -- never on a
    sibling resource -- and CloudFormation's system tags land only where its schema says they do
    (present on the SSM parameter, absent on the DynamoDB table).
    """
    cfn = ctx.client("cloudformation")
    dynamodb = ctx.client("dynamodb")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-xsvc-combtags-")
    table_name = ctx.unique_name("sim2real-xsvc-combtags-tbl-")
    parameter_name = ctx.unique_name("sim2real-xsvc-combtags-param-")
    template = _template(table_name, parameter_name)

    cfn.create_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "stack-tag", "Value": "sv"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended in {status!r}, expected CREATE_COMPLETE"

    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    table_arn = _outputs(cfn, stack)["TableArn"]
    table_tags = _table_tags(dynamodb, table_arn)
    assert table_tags == {"table-resource-tag": "tv", "stack-tag": "sv"}, (
        f"the table's own Tags and the stack's Tags should combine, with neither the sibling "
        f"parameter's tag nor a CloudFormation system tag (DynamoDB's schema marks "
        f"cloudFormationSystemTags false); got {table_tags!r}"
    )

    param_tags = _param_tags(ssm, parameter_name)
    want_param = {
        "param-resource-tag": "pv",
        "stack-tag": "sv",
        "aws:cloudformation:stack-name": stack,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": "Parameter",
    }
    assert param_tags == want_param, (
        f"the parameter's own Tags, the stack's Tags and the three aws:cloudformation:* system "
        f"tags should combine, without the sibling table's tag; expected {want_param!r}, "
        f"got {param_tags!r}"
    )


def _table_tags(dynamodb, table_arn: str) -> dict:
    resp = dynamodb.list_tags_of_resource(ResourceArn=table_arn)
    tags_list = list(resp.get("Tags", []))
    next_token = resp.get("NextToken")
    while next_token:
        resp = dynamodb.list_tags_of_resource(ResourceArn=table_arn, NextToken=next_token)
        tags_list += resp.get("Tags", [])
        next_token = resp.get("NextToken")
    return {t["Key"]: t["Value"] for t in tags_list}


def _param_tags(ssm, parameter_name: str) -> dict:
    resp = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=parameter_name)
    return {t["Key"]: t["Value"] for t in resp.get("TagList", [])}


def _outputs(cfn, stack_name: str) -> dict:
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_name} still deleting after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
