"""stack-tags-propagate-to-table-without-system-tags-and-update-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-tags-propagate-to-table-without-system-tags-and-update-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

def _template(table_name: str) -> str:
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
                },
            },
        },
        "Outputs": {"TableArn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack-level Tag propagates to a DynamoDB table (DynamoDB's own ListTagsOfResource) but
    CloudFormation's aws:cloudformation:* system tags do not; an UpdateStack tag change replaces
    the table's tag in place, on the same table ARN.
    """
    cfn = ctx.client("cloudformation")
    dynamodb = ctx.client("dynamodb")

    stack = ctx.unique_name("sim2real-xsvc-ddbtags-")
    table_name = ctx.unique_name("sim2real-xsvc-ddbtags-tbl-")
    template = _template(table_name)

    cfn.create_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real-env", "Value": "v1"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended in {status!r}, expected CREATE_COMPLETE"

    table_arn = _outputs(cfn, stack)["TableArn"]
    identity = _table_identity(dynamodb, table_name)
    tag_map = _table_tags(dynamodb, table_arn)
    assert tag_map == {"sim2real-env": "v1"}, (
        f"expected exactly the stack tag on the DynamoDB table, with no aws:cloudformation:* "
        f"system tags; got {tag_map!r}"
    )

    cfn.update_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real-env", "Value": "v2"}],
    )
    status = _wait_terminal(cfn, stack)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} update ended in {status!r}, expected UPDATE_COMPLETE"

    table_arn_after = _outputs(cfn, stack)["TableArn"]
    assert table_arn_after == table_arn, (
        f"the table's ARN changed from {table_arn!r} to {table_arn_after!r} across a tags-only "
        f"UpdateStack; the resource should have been updated in place, not replaced"
    )
    identity_after = _table_identity(dynamodb, table_name)
    assert identity_after == identity, (
        f"the table's (TableId, CreationDateTime) changed from {identity!r} to {identity_after!r} "
        f"across a tags-only UpdateStack; the table was recreated, not updated in place"
    )
    tag_map_after = _table_tags(dynamodb, table_arn)
    assert tag_map_after == {"sim2real-env": "v2"}, (
        f"after the stack tag update, ListTagsOfResource on the same table ARN returned "
        f"{tag_map_after!r}, expected exactly {{'sim2real-env': 'v2'}}"
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


def _table_identity(dynamodb, table_name: str) -> tuple:
    """DynamoDB-minted identity: a recreated table gets a new TableId and CreationDateTime."""
    table = dynamodb.describe_table(TableName=table_name)["Table"]
    return table["TableId"], table["CreationDateTime"]


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
