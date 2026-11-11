"""deploy-dynamodb-2-deletion-protection-blocks-stack-delete."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-2-deletion-protection-blocks-stack-delete"
GROUP = "deploy-lifecycle-enforcement"
SERVICES = ["cloudformation", "dynamodb"]

STACK_TIMEOUT_S = 600.0
TABLE_TIMEOUT_S = 180.0
TEARDOWN_TIMEOUT_S = 300.0
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}
_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED"}
NOT_FOUND = "ResourceNotFoundException"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """DeleteStack on a deletion-protected table ends DELETE_FAILED with the table ACTIVE and its item
    readable, and UpdateStack is then refused; unprotecting the table lets DeleteStack complete. A
    twin stack unprotected via UpdateStack deletes cleanly.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    key = {"pk": {"S": "survivor"}}
    item = {"pk": {"S": "survivor"}, "body": {"S": "written-before-delete-stack"}}

    # Both stacks are created up front so their deploys overlap; each teardown is registered
    # IMMEDIATELY after its create. A protected table survives a bare DeleteStack, so the teardown
    # turns protection off on the live table before deleting -- whatever beat the check died in.
    ok_table = ctx.unique_name("sim2real-xsvc-dpok-")
    ok_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-xsvc-dpokstk-"),
        TemplateBody=_template(protected=True),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": ok_table}],
    )["StackId"]
    ctx.on_cleanup(lambda: _force_teardown(cfn, ddb, ok_id, ok_table))

    table = ctx.unique_name("sim2real-xsvc-dpt-")
    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-xsvc-dptstk-"),
        TemplateBody=_template(protected=True),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": table}],
    )["StackId"]
    ctx.on_cleanup(lambda: _force_teardown(cfn, ddb, stack_id, table))

    for sid, tname in ((ok_id, ok_table), (stack_id, table)):
        status = _poll(cfn, sid, _CREATE_TERMINAL)
        assert status == "CREATE_COMPLETE", f"the protected-table stack must deploy; got {status!r}"
        desc = ddb.describe_table(TableName=tname)["Table"]
        assert desc.get("DeletionProtectionEnabled") is True, (
            f"the template sets DeletionProtectionEnabled: true and the live table must carry it; "
            f"DescribeTable on {tname!r} says {desc.get('DeletionProtectionEnabled')!r}"
        )
        ddb.put_item(TableName=tname, Item=item)
        got = ddb.get_item(TableName=tname, Key=key, ConsistentRead=True).get("Item")
        assert got == item, f"the deployed table must serve the item; wrote {item!r}, read {got!r}"

    # A DELETE_FAILED stack cannot be updated, so the flip-via-UpdateStack control uses a twin stack.
    cfn.update_stack(
        StackName=ok_id,
        TemplateBody=_template(protected=False),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": ok_table}],
    )
    status = _poll(cfn, ok_id, _UPDATE_TERMINAL)
    assert status == "UPDATE_COMPLETE", (
        f"UpdateStack setting DeletionProtectionEnabled: false must complete; got {status!r}"
    )
    desc = ddb.describe_table(TableName=ok_table)["Table"]
    assert desc.get("DeletionProtectionEnabled") is False, (
        f"the stack update must reach the live table; DeletionProtectionEnabled is "
        f"{desc.get('DeletionProtectionEnabled')!r}"
    )
    got = ddb.get_item(TableName=ok_table, Key=key, ConsistentRead=True).get("Item")
    assert got == item, (
        f"flipping deletion protection is an in-place update and must not replace the table; read {got!r}"
    )
    cfn.delete_stack(StackName=ok_id)
    status = _poll(cfn, ok_id, _DELETE_TERMINAL)
    assert status == "DELETE_COMPLETE", (
        f"with deletion protection flipped off via UpdateStack the stack delete must succeed; got "
        f"{status!r}"
    )
    err = _client_error(lambda: ddb.describe_table(TableName=ok_table))
    assert err.get("Code") == NOT_FOUND, (
        f"DELETE_COMPLETE must mean the table is gone; DescribeTable on {ok_table!r} gave "
        f"{err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == f"Requested resource not found: Table: {ok_table} not found", (
        f"DescribeTable on the deleted {ok_table!r}: unexpected message {err.get('Message')!r}"
    )

    cfn.delete_stack(StackName=stack_id)
    status = _poll(cfn, stack_id, _DELETE_TERMINAL)
    assert status == "DELETE_FAILED", (
        f"deletion protection must block the stack delete; got {status!r}. DELETE_COMPLETE means the "
        f"target ignored DeletionProtectionEnabled and destroyed the table"
    )
    reason = " | ".join(
        e.get("ResourceStatusReason", "") for e in _events(cfn, stack_id)
        if e["LogicalResourceId"] == "Table" and e["ResourceStatus"] == "DELETE_FAILED"
    )
    # message varies: the handler reason embeds a per-call Request ID and RequestToken.
    assert "deletion protection" in reason.lower(), (
        f"the table's DELETE_FAILED must name deletion protection as the cause; got {reason!r}. Any "
        f"other cause -- a throttle, a permission -- also reaches DELETE_FAILED"
    )
    desc = ddb.describe_table(TableName=table)["Table"]
    assert desc["TableStatus"] == "ACTIVE", (
        f"the protected table must still be ACTIVE after the blocked delete; got {desc['TableStatus']!r}"
    )
    assert desc.get("DeletionProtectionEnabled") is True, (
        f"the blocked delete must leave protection on; got {desc.get('DeletionProtectionEnabled')!r}"
    )
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert got == item, f"the item must survive the blocked stack delete; read {got!r}"

    err = _client_error(lambda: cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(protected=False),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": table}],
    ))
    assert err.get("Code") == "ValidationError", (
        f"UpdateStack on a DELETE_FAILED stack must be refused with ValidationError; got "
        f"{err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == f"Stack:{stack_id} is in DELETE_FAILED state and can not be updated.", (
        f"the refusal must name the DELETE_FAILED state; got {err.get('Message')!r}"
    )

    # Recovery the way a customer must: UpdateTable on the live table, then DeleteStack again.
    ddb.update_table(TableName=table, DeletionProtectionEnabled=False)
    _wait_table(ddb, table, lambda t: t["TableStatus"] == "ACTIVE"
                and t.get("DeletionProtectionEnabled") is False)
    cfn.delete_stack(StackName=stack_id)
    status = _poll(cfn, stack_id, _DELETE_TERMINAL)
    assert status == "DELETE_COMPLETE", (
        f"with deletion protection off the retried stack delete must succeed; got {status!r}"
    )
    err = _client_error(lambda: ddb.describe_table(TableName=table))
    assert err.get("Code") == NOT_FOUND, (
        f"DELETE_COMPLETE must mean the table is gone; DescribeTable on {table!r} gave "
        f"{err.get('Code')!r}: {err.get('Message')!r}"
    )


def _template(*, protected: bool) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"TableName": {"Type": "String"}},
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": {"Ref": "TableName"},
                        "BillingMode": "PAY_PER_REQUEST",
                        "DeletionProtectionEnabled": protected,
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    },
                }
            },
        }
    )


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


def _wait_table(ddb, table: str, cond) -> dict:
    deadline = time.monotonic() + TABLE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        if cond(last):
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"table {table!r} did not reach the expected state within {TABLE_TIMEOUT_S}s; last "
        f"status={last and last.get('TableStatus')!r} "
        f"protection={last and last.get('DeletionProtectionEnabled')!r}"
    )


def _unprotect(ddb, table: str) -> bool:
    """Wait for the table to be ACTIVE and turn deletion protection off. True if the table is gone or
    now unprotected."""
    deadline = time.monotonic() + TABLE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            t = ddb.describe_table(TableName=table)["Table"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code") == NOT_FOUND
        if t["TableStatus"] == "ACTIVE":
            if not t.get("DeletionProtectionEnabled"):
                return True
            try:
                ddb.update_table(TableName=table, DeletionProtectionEnabled=False)
            except ClientError as err:
                if err.response["Error"]["Code"] not in (
                    "ResourceNotFoundException",
                    "TableNotFoundException",
                ):
                    raise
        time.sleep(5.0)
    return False


def _force_teardown(cfn, ddb, stack_id: str, table: str) -> None:
    """Undo the stack whatever state it was abandoned in. A failure raises."""
    _leaks: list = []
    if not _unprotect(ddb, table):
        _leaks.append((f"could not turn deletion protection off on table {table!r}", None))
    for _attempt in range(2):
        try:
            if cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
                break
            cfn.delete_stack(StackName=stack_id)
        except ClientError as exc:
            _leaks.append((f"delete_stack {stack_id!r} refused: {exc}", exc))
            break
        deadline = time.monotonic() + TEARDOWN_TIMEOUT_S
        status = None
        while time.monotonic() < deadline:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            if status in _DELETE_TERMINAL:
                break
            time.sleep(5.0)
        if status == "DELETE_COMPLETE":
            break
        _unprotect(ddb, table)
    else:
        _leaks.append((f"stack {stack_id!r} / table {table!r} did not delete", None))
    try:
        ddb.describe_table(TableName=table)
        _leaks.append((f"table {table!r} still exists after teardown", None))
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
