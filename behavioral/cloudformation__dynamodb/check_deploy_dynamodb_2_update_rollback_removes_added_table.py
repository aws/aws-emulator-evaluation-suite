"""deploy-dynamodb-2-update-rollback-removes-added-table."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-2-update-rollback-removes-added-table"
GROUP = "deploy-lifecycle-enforcement"
SERVICES = ["cloudformation", "dynamodb"]

STACK_TIMEOUT_S = 600.0
TEARDOWN_TIMEOUT_S = 300.0
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED"}
NOT_FOUND = "ResourceNotFoundException"


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An update adding a valid table plus a broken one rolls back selectively: the added table is
    created then deleted while the original table keeps its item; the same update without the
    broken table then completes and the added table serves data.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    orig = ctx.unique_name("sim2real-xsvc-urO-")
    added = ctx.unique_name("sim2real-xsvc-urN-")
    broken = ctx.unique_name("sim2real-xsvc-urB-")
    params = [
        {"ParameterKey": "OrigName", "ParameterValue": orig},
        {"ParameterKey": "AddedName", "ParameterValue": added},
        {"ParameterKey": "BrokenName", "ParameterValue": broken},
    ]
    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-xsvc-urstk-"),
        TemplateBody=_template(add=False, broken=False),
        Parameters=params,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    status = _poll(cfn, stack_id, _CREATE_TERMINAL)
    assert status == "CREATE_COMPLETE", f"the one-table base stack must deploy; got {status!r}"
    key = {"pk": {"S": "pre-update"}}
    item = {"pk": {"S": "pre-update"}, "v": {"S": "must-survive-the-rollback"}}
    ddb.put_item(TableName=orig, Item=item)

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(add=True, broken=True),
                     Parameters=params)
    status = _poll(cfn, stack_id, _UPDATE_TERMINAL)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update adding a table whose KeySchema names an undeclared attribute must roll back; got "
        f"{status!r}"
    )

    events = list(reversed(_events(cfn, stack_id)))  # oldest first
    added_timeline = [e["ResourceStatus"] for e in events if e["LogicalResourceId"] == "AddedTable"]
    assert "CREATE_COMPLETE" in added_timeline and "DELETE_COMPLETE" in added_timeline, (
        f"DependsOn forces the added valid table to be built before the broken one, and the rollback "
        f"must then delete it; its timeline was {added_timeline!r}"
    )
    assert added_timeline.index("CREATE_COMPLETE") < added_timeline.index("DELETE_COMPLETE"), (
        f"the added table must be created and THEN deleted; timeline {added_timeline!r}"
    )
    broken_reason = " | ".join(
        e.get("ResourceStatusReason", "") for e in events
        if e["LogicalResourceId"] == "BrokenTable" and e["ResourceStatus"] == "CREATE_FAILED"
    )
    assert "not defined in AttributeDefinitions" in broken_reason, (
        f"the broken table's CREATE_FAILED must state the rule it broke; got {broken_reason!r}"
    )
    orig_states = {e["ResourceStatus"] for e in events if e["LogicalResourceId"] == "OrigTable"}
    assert "DELETE_COMPLETE" not in orig_states and "DELETE_IN_PROGRESS" not in orig_states, (
        f"an update rollback must not touch the pre-existing table; its states were "
        f"{sorted(orig_states)!r}"
    )

    for name, what in ((added, "the added valid table"), (broken, "the broken table")):
        err = _client_error(lambda n=name: ddb.describe_table(TableName=n))
        assert err.get("Code") == NOT_FOUND, (
            f"after UPDATE_ROLLBACK_COMPLETE {what} {name!r} must not exist; DescribeTable gave "
            f"{err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == f"Requested resource not found: Table: {name} not found", (
            f"DescribeTable {NOT_FOUND} message for {what}: {err.get('Message')!r}"
        )
    err = _client_error(lambda: ddb.put_item(TableName=added, Item={"pk": {"S": "x"}}))
    assert err.get("Code") == NOT_FOUND, (
        f"a rolled-back table must not accept writes; PutItem gave {err.get('Code')!r}: "
        f"{err.get('Message')!r}"
    )
    assert err.get("Message") == "Requested resource not found", (
        f"PutItem {NOT_FOUND} message: {err.get('Message')!r}"
    )
    got = ddb.get_item(TableName=orig, Key=key, ConsistentRead=True).get("Item")
    assert got == item, f"the original table's item must survive the update rollback; read {got!r}"
    logical = sorted(r["LogicalResourceId"] for page in
                     cfn.get_paginator("list_stack_resources").paginate(StackName=stack_id)
                     for r in page["StackResourceSummaries"])
    assert logical == ["OrigTable"], (
        f"after the rollback the stack must own only its original table; it lists {logical!r}"
    )

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(add=True, broken=False),
                     Parameters=params)
    status = _poll(cfn, stack_id, _UPDATE_TERMINAL)
    assert status == "UPDATE_COMPLETE", (
        f"the update adding only the valid table must complete; got {status!r}"
    )
    new_item = {"pk": {"S": "post-update"}, "v": {"S": "served-by-the-added-table"}}
    ddb.put_item(TableName=added, Item=new_item)
    got = ddb.get_item(TableName=added, Key={"pk": {"S": "post-update"}},
                       ConsistentRead=True).get("Item")
    assert got == new_item, f"the added table must serve data; wrote {new_item!r}, read {got!r}"
    got = ddb.get_item(TableName=orig, Key=key, ConsistentRead=True).get("Item")
    assert got == item, f"the original table must still hold its item; read {got!r}"


def _table(name_param: str, *, broken: bool = False, depends_on: str | None = None) -> dict:
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    if broken:
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})  # sk is never declared below
    res = {
        "Type": "AWS::DynamoDB::Table",
        "Properties": {
            "TableName": {"Ref": name_param},
            "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": keys,
        },
    }
    if depends_on:
        res["DependsOn"] = depends_on
    return res


def _template(*, add: bool, broken: bool) -> str:
    resources = {"OrigTable": _table("OrigName")}
    if add:
        resources["AddedTable"] = _table("AddedName")
    if broken:
        resources["BrokenTable"] = _table("BrokenName", broken=True, depends_on="AddedTable")
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {p: {"Type": "String"} for p in ("OrigName", "AddedName", "BrokenName")},
        "Resources": resources,
    })


def _poll(cfn, stack_id: str, terminal: set) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_id!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"(last={last!r})"
    )


def _events(cfn, stack_id: str) -> list:
    return [
        event
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for event in page["StackEvents"]
    ]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete and wait to a terminal state; never raise, but say so on stderr if it did not converge."""
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        raise RuntimeError(f"delete_stack {stack_id!r} refused: {exc}") from exc
    deadline = time.monotonic() + TEARDOWN_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if not (
                err.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in err.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_id!r} did not delete (last status {status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
