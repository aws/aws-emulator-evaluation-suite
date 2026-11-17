"""deploy-table-stream-arn-getatt-without-stream-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-table-stream-arn-getatt-without-stream-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

def _wait(cf, stack_id: str, budget_s: float = 600.0) -> dict:
    """The stack once it leaves every *_IN_PROGRESS state."""
    deadline = time.monotonic() + budget_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {budget_s}s")
        time.sleep(4)


def _delete_stack(cf, stack_id: str):
    """A cleanup that deletes the stack and raises unless it reaches DELETE_COMPLETE."""

    def run_delete() -> None:
        cf.delete_stack(StackName=stack_id)
        status = _wait(cf, stack_id)["StackStatus"]
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack delete ended {status!r}")

    return run_delete


def _events(cf, stack_id: str) -> list:
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(name: str, stream: bool) -> str:
    """A named on-demand table, with a KEYS_ONLY stream when ``stream``, outputting its StreamArn."""
    props = {
        "TableName": name,
        "BillingMode": "PAY_PER_REQUEST",
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "Tags": [{"Key": "sim2real", "Value": name}],
    }
    if stream:
        props["StreamSpecification"] = {"StreamViewType": "KEYS_ONLY"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Table": {"Type": "AWS::DynamoDB::Table", "Properties": props}},
        "Outputs": {"Stream": {"Value": {"Fn::GetAtt": ["Table", "StreamArn"]}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Fn::GetAtt StreamArn on a table with no stream fails the create and rolls the table back,
    while the same output on a table with a stream resolves to the table's LatestStreamArn."""
    cf = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stacks = {}
    for key, stream in (("withstream", True), ("nostream", False)):
        name = ctx.unique_name(f"sim2real-behav-{key}-")
        stack_id = cf.create_stack(StackName=name, TemplateBody=_template(name, stream),
                                   Tags=[{"Key": "sim2real", "Value": name}])["StackId"]
        ctx.on_cleanup(_delete_stack(cf, stack_id))
        stacks[key] = (name, stack_id)

    name, stack_id = stacks["withstream"]
    control = _wait(cf, stack_id)
    assert control["StackStatus"] == "CREATE_COMPLETE", f"control stack ended {control['StackStatus']!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in control.get("Outputs", [])}
    table = ddb.describe_table(TableName=name)["Table"]
    assert table["StreamSpecification"] == {"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"}, (
        f"control table stream {table.get('StreamSpecification')!r}"
    )
    assert sorted(outputs) == ["Stream"], f"control output keys {sorted(outputs)!r}"
    assert outputs["Stream"] == table["LatestStreamArn"], "StreamArn output differs from the table's LatestStreamArn"

    name, stack_id = stacks["nostream"]
    broken = _wait(cf, stack_id)
    assert broken["StackStatus"] == "ROLLBACK_COMPLETE", f"no-stream stack ended {broken['StackStatus']!r}"
    assert "Outputs" not in broken, f"rolled-back stack shows outputs {broken['Outputs']!r}"
    events = _events(cf, stack_id)
    reasons = [e.get("ResourceStatusReason") for e in events
               if e["LogicalResourceId"] == name and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    assert reasons == ["Attribute 'StreamArn' does not exist. Rollback requested by user."], (
        f"rollback reasons {reasons!r}"
    )
    table_events = [e["ResourceStatus"] for e in events if e["LogicalResourceId"] == "Table"]
    assert "CREATE_COMPLETE" in table_events and "DELETE_COMPLETE" in table_events, (
        f"table events {table_events!r}"
    )
    code, msg = _error(lambda: ddb.describe_table(TableName=name))
    assert code == "ResourceNotFoundException", f"rolled-back table lookup code {code!r}"
    assert msg == f"Requested resource not found: Table: {name} not found", f"table lookup message {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
