"""deploy-dynamodb-2-multi-resource-rollback."""
# `DependsOn: TableA` on table B forces A to finish creating before B is attempted, so A's
# CREATE_COMPLETE event exists and the rollback must actively delete a table that was built.
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-2-multi-resource-rollback"
GROUP = "deploy-lifecycle-enforcement"
SERVICES = ["cloudformation", "dynamodb"]

STACK_TIMEOUT_S = 600.0
TEARDOWN_TIMEOUT_S = 300.0
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
NOT_FOUND = "ResourceNotFoundException"


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A stack of table A plus table B (DependsOn A, B's KeySchema naming an undeclared attribute)
    reaches ROLLBACK_COMPLETE and deletes the built table A, so DescribeTable and PutItem on A raise
    ResourceNotFoundException with exact messages; a control stack with only table A serves items."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    # --- Beat 1: positive control -- a twin stack holding only a correct table A ------------------
    # First, so a later failure cannot be read as "this target refuses DynamoDB templates".
    ok_table = ctx.unique_name("sim2real-xsvc-rbok-")
    ok_stack = ctx.unique_name("sim2real-xsvc-rbokstk-")
    ok_id = cfn.create_stack(
        StackName=ok_stack,
        TemplateBody=_template(with_broken_b=False),
        Parameters=[{"ParameterKey": "TableAName", "ParameterValue": ok_table}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, ok_id))
    ok_status = _poll_stack(cfn, ok_id)
    assert ok_status == "CREATE_COMPLETE", (
        f"the control stack (table A only, correctly defined) must deploy; got {ok_status!r}"
    )
    ok_desc = ddb.describe_table(TableName=ok_table)["Table"]
    assert ok_desc["TableStatus"] == "ACTIVE", (
        f"the control table must be ACTIVE once its stack is CREATE_COMPLETE; got "
        f"{ok_desc['TableStatus']!r}"
    )
    item = {"pk": {"S": "control-1"}, "payload": {"S": "served-by-the-control-stack"},
            "n": {"N": "42"}}
    ddb.put_item(TableName=ok_table, Item=item)
    got = ddb.get_item(TableName=ok_table, Key={"pk": {"S": "control-1"}},
                       ConsistentRead=True).get("Item")
    assert got == item, f"the control table must round-trip the item exactly; wrote {item!r}, read {got!r}"

    # --- Beat 2: the negative -- A is valid, B (DependsOn A) names an undeclared key attribute ------
    bad_a = ctx.unique_name("sim2real-xsvc-rbA-")
    bad_b = ctx.unique_name("sim2real-xsvc-rbB-")
    bad_stack = ctx.unique_name("sim2real-xsvc-rbbadstk-")
    created = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(with_broken_b=True),
        Parameters=[
            {"ParameterKey": "TableAName", "ParameterValue": bad_a},
            {"ParameterKey": "TableBName", "ParameterValue": bad_b},
        ],
    )
    bad_id = created.get("StackId")
    # A rolled-back stack still EXISTS and needs teardown; registered before the first assertion.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_id or bad_stack))
    assert bad_id, f"CreateStack must return a StackId even for a template that will fail; got {created!r}"

    bad_status = _poll_stack(cfn, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a stack whose table B names a key attribute absent from AttributeDefinitions must roll back; "
        f"got {bad_status!r}. A target that builds the broken table verbatim reaches CREATE_COMPLETE"
    )

    events = _events(cfn, bad_id)
    a_states = [e["ResourceStatus"] for e in events if e["LogicalResourceId"] == "TableA"]
    b_events = [e for e in events if e["LogicalResourceId"] == "TableB"]
    b_states = [e["ResourceStatus"] for e in b_events]
    # Events come newest-first; reverse to read the life of A in order.
    a_timeline = list(reversed(a_states))
    assert "CREATE_COMPLETE" in a_timeline, (
        f"DependsOn forces table A to finish before B starts, so A must have reached CREATE_COMPLETE; "
        f"A's timeline was {a_timeline!r}"
    )
    assert "DELETE_COMPLETE" in a_timeline, (
        f"rollback must DELETE the already-built table A; A's timeline was {a_timeline!r}"
    )
    assert a_timeline.index("CREATE_COMPLETE") < a_timeline.index("DELETE_COMPLETE"), (
        f"table A must be created and THEN deleted by the rollback; A's timeline was {a_timeline!r}"
    )
    assert "CREATE_FAILED" in b_states, (
        f"table B must be the resource that failed; B's states were {b_states!r}"
    )
    b_reason = " | ".join(e.get("ResourceStatusReason", "") for e in b_events
                          if e["ResourceStatus"] == "CREATE_FAILED")
    # The reason ends in "(RequestToken: <per-call uuid>, HandlerErrorCode: <code>)"; the token varies
    # per run, so the handler message and the handler error code are compared exactly on either side.
    handler_message, _, handler_tail = b_reason.partition(" (RequestToken: ")
    expected = (
        'Resource handler returned message: "An attribute referenced in a KeySchema element is not '
        'defined in AttributeDefinitions"'
    )
    assert handler_message == expected, (
        f"B's failure must state the rule it broke; expected {expected!r}, got {b_reason!r}. Any other "
        f"cause -- a throttle, a quota, a permission -- also reaches ROLLBACK_COMPLETE"
    )
    handler_code = handler_tail.rpartition(", HandlerErrorCode: ")[2]
    assert handler_code == "InvalidRequest)", f"expected HandlerErrorCode InvalidRequest, got {b_reason!r}"

    # --- Beat 3: effect-absent at DynamoDB -- table A is gone on both planes ----------------------
    err = _client_error(lambda: ddb.describe_table(TableName=bad_a))
    assert err.get("Code") == NOT_FOUND, (
        f"rollback must have deleted table A {bad_a!r}; DescribeTable gave {err.get('Code')!r}: "
        f"{err.get('Message')!r}"
    )
    expected = f"Requested resource not found: Table: {bad_a} not found"
    assert err.get("Message") == expected, f"expected {expected!r}, got {err.get('Message')!r}"
    err = _client_error(lambda: ddb.put_item(TableName=bad_a, Item={"pk": {"S": "after-rollback"}}))
    assert err.get("Code") == NOT_FOUND, (
        f"a rolled-back table must not accept writes; PutItem on {bad_a!r} gave {err.get('Code')!r}: "
        f"{err.get('Message')!r}"
    )
    expected = "Requested resource not found"
    assert err.get("Message") == expected, f"expected {expected!r}, got {err.get('Message')!r}"
    err = _client_error(lambda: ddb.describe_table(TableName=bad_b))
    assert err.get("Code") == NOT_FOUND, (
        f"the invalid table B {bad_b!r} must never have been built; DescribeTable gave "
        f"{err.get('Code')!r}: {err.get('Message')!r}"
    )
    expected = f"Requested resource not found: Table: {bad_b} not found"
    assert err.get("Message") == expected, f"expected {expected!r}, got {err.get('Message')!r}"

    # --- Beat 4: the control is untouched by the sibling stack's rollback --------------------------
    still = ddb.get_item(TableName=ok_table, Key={"pk": {"S": "control-1"}},
                         ConsistentRead=True).get("Item")
    assert still == item, (
        f"the control stack's table must be unaffected by another stack's rollback; read {still!r}"
    )


def _template(*, with_broken_b: bool) -> str:
    """Table A is always valid. With `with_broken_b`, table B (DependsOn A) is keyed on (pk, sk) but
    declares only `pk` in AttributeDefinitions."""
    params = {"TableAName": {"Type": "String"}}
    resources = {
        "TableA": {
            "Type": "AWS::DynamoDB::Table",
            "Properties": {
                "TableName": {"Ref": "TableAName"},
                "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            },
        }
    }
    if with_broken_b:
        params["TableBName"] = {"Type": "String"}
        resources["TableB"] = {
            "Type": "AWS::DynamoDB::Table",
            "DependsOn": "TableA",
            "Properties": {
                "TableName": {"Ref": "TableBName"},
                "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
            },
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Parameters": params,
                       "Resources": resources})


def _poll_stack(cfn, stack_id: str) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _CREATE_TERMINAL:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_id!r} did not reach a create-terminal state within {STACK_TIMEOUT_S}s "
        f"(last={last!r})"
    )


def _events(cfn, stack_id: str) -> list:
    return [
        event
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for event in page["StackEvents"]
    ]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, so a target that
    accepts a request AWS refuses is reported as such, not as an error-code mismatch."""
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
