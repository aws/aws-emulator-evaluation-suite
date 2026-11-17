"""cfn-events-connection-and-api-destination-update-in-place-and-replacement."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-events-connection-and-api-destination-update-in-place-and-replacement"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]

#: A stack transition takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_CAP_S = 600.0
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _auth_block(auth_type: str, label: str) -> dict:
    if auth_type == "BASIC":
        return {"BasicAuthParameters": {"Username": label, "Password": {"Ref": "ConnSecret"}}}
    return {"ApiKeyAuthParameters": {"ApiKeyName": label, "ApiKeyValue": {"Ref": "ConnSecret"}}}


def _template(cfg: dict) -> tuple[str, list[dict]]:
    """A Connection and an ApiDestination that references it, both retained across replacement."""
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ConnSecret": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "Connection": {
                "Type": "AWS::Events::Connection",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "Name": cfg["conn_name"],
                    "Description": cfg["conn_desc"],
                    "AuthorizationType": cfg["auth_type"],
                    "AuthParameters": _auth_block(cfg["auth_type"], cfg["auth_label"]),
                },
            },
            "Destination": {
                "Type": "AWS::Events::ApiDestination",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "Name": cfg["dest_name"],
                    "Description": cfg["dest_desc"],
                    "ConnectionArn": {"Fn::GetAtt": ["Connection", "Arn"]},
                    "InvocationEndpoint": cfg["endpoint"],
                    "HttpMethod": cfg["http_method"],
                    "InvocationRateLimitPerSecond": cfg["rate"],
                },
            },
        },
        "Outputs": {
            "ConnectionRef": {"Value": {"Ref": "Connection"}},
            "ConnectionArn": {"Value": {"Fn::GetAtt": ["Connection", "Arn"]}},
            "DestinationRef": {"Value": {"Ref": "Destination"}},
            "DestinationArn": {"Value": {"Fn::GetAtt": ["Destination", "Arn"]}},
        },
    }
    return json.dumps(body), [{"ParameterKey": "ConnSecret", "ParameterValue": cfg["secret"]}]


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A stack-provisioned AWS::Events::Connection and AWS::Events::ApiDestination take a
    mutable-property update in place, then a Name change through replacement (old one retained);
    a dependent ApiDestination's ConnectionArn follows its Connection's replacement in place.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-connection.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-apidestination.html
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    conn1 = ctx.unique_name("sim2real-behav-evconn-a-")
    conn2 = ctx.unique_name("sim2real-behav-evconn-b-")
    dest1 = ctx.unique_name("sim2real-behav-evdest-a-")
    dest2 = ctx.unique_name("sim2real-behav-evdest-b-")
    stack_name = ctx.unique_name("sim2real-behav-evconnstk-")
    endpoint = f"https://example.com/{ctx.unique_name('sim2real-evdest-')}"

    # The resources a replacement retains outlive the stack, so the check deletes them itself.
    ctx.on_cleanup(lambda: _delete_connection(events, conn1))
    ctx.on_cleanup(lambda: _delete_destination(events, dest1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: both resources, read back through EventBridge's own API --------------
    cfg = {
        "conn_name": conn1, "conn_desc": "first connection", "auth_type": "BASIC",
        "auth_label": "sim2real-user", "secret": "sim2real-basic-password",
        "dest_name": dest1, "dest_desc": "first destination", "endpoint": endpoint,
        "http_method": "GET", "rate": 2,
    }
    body, params = _template(cfg)
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=body, Parameters=params, Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    out = _outputs(stack)
    assert out["ConnectionRef"] == conn1, f"Ref on Connection should be its name: {out!r}"
    assert out["DestinationRef"] == dest1, f"Ref on Destination should be its name: {out!r}"

    conn = _assert_connection(events, conn1, desc="first connection", auth_type="BASIC",
                               label="sim2real-user", arn=out["ConnectionArn"])
    _assert_connection_state(ctx, events, conn1, "AUTHORIZED")
    _assert_destination(events, dest1, desc="first destination", conn_arn=conn["ConnectionArn"],
                         endpoint=endpoint, method="GET", rate=2, arn=out["DestinationArn"])

    conn1_physical_before = _physical(cfn, stack_id, "Connection")
    dest1_physical_before = _physical(cfn, stack_id, "Destination")

    # ---- 2. in-place update: mutable properties on both resources, no name change ----------
    cfg2 = dict(cfg, conn_desc="second connection", auth_type="API_KEY",
                auth_label="sim2real-key-name", secret="sim2real-api-key-value",
                dest_desc="second destination", http_method="PUT", rate=10)
    rows = _update(ctx, cfn, stack_id, *_template(cfg2))
    _assert_in_place(rows, "Connection", conn1_physical_before)
    _assert_in_place(rows, "Destination", dest1_physical_before)

    conn = _assert_connection(events, conn1, desc="second connection", auth_type="API_KEY",
                               label="sim2real-key-name", arn=out["ConnectionArn"])
    _assert_connection_state(ctx, events, conn1, "AUTHORIZED")
    _assert_destination(events, dest1, desc="second destination", conn_arn=conn["ConnectionArn"],
                         endpoint=endpoint, method="PUT", rate=10, arn=out["DestinationArn"])

    # ---- 3. replacement update: only the ApiDestination's Name changes --------------------
    cfg3 = dict(cfg2, dest_name=dest2)
    rows = _update(ctx, cfn, stack_id, *_template(cfg3))
    _assert_replaced_and_retained(rows, "Destination", dest1, dest2)
    dest2_arn = _outputs(_stack(cfn, stack_id))["DestinationArn"]

    # the retained old destination still answers, unchanged since step 2
    _assert_destination(events, dest1, desc="second destination", conn_arn=conn["ConnectionArn"],
                         endpoint=endpoint, method="PUT", rate=10, arn=out["DestinationArn"])
    _assert_destination(events, dest2, desc="second destination", conn_arn=conn["ConnectionArn"],
                         endpoint=endpoint, method="PUT", rate=10, arn=dest2_arn)
    assert _physical(cfn, stack_id, "Connection") == conn1_physical_before, (
        "changing only the Destination's Name must not touch the Connection"
    )

    # ---- 4. replacement update: only the Connection's Name changes ------------------------
    dest2_physical_before = _physical(cfn, stack_id, "Destination")
    cfg4 = dict(cfg3, conn_name=conn2)
    rows = _update(ctx, cfn, stack_id, *_template(cfg4))
    _assert_replaced_and_retained(rows, "Connection", conn1, conn2)
    _assert_in_place(rows, "Destination", dest2_physical_before)

    new_conn = _assert_connection(events, conn2, desc="second connection", auth_type="API_KEY",
                                   label="sim2real-key-name",
                                   arn=_outputs(_stack(cfn, stack_id))["ConnectionArn"])
    _assert_connection_state(ctx, events, conn2, "AUTHORIZED")
    # the retained old connection still answers, unchanged since step 2
    _assert_connection(events, conn1, desc="second connection", auth_type="API_KEY",
                        label="sim2real-key-name", arn=out["ConnectionArn"])
    # the dependent destination's ConnectionArn followed the replacement, in place
    _assert_destination(events, dest2, desc="second destination", conn_arn=new_conn["ConnectionArn"],
                         endpoint=endpoint, method="PUT", rate=10, arn=dest2_arn)

    # ---- 5. DeleteStack: only the resources it still owns are gone ------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _error(lambda: events.describe_api_destination(Name=dest2))
    want = ("ResourceNotFoundException",
            f"Failed to describe the api-destination(s). An api-destination '{dest2}' does not exist.")
    assert got == want, f"DescribeApiDestination after DeleteStack: {got!r}, expected {want!r}"
    got = _error(lambda: events.describe_connection(Name=conn2))
    want = ("ResourceNotFoundException",
            f"Failed to describe the connection(s). Connection '{conn2}' does not exist.")
    assert got == want, f"DescribeConnection after DeleteStack: {got!r}, expected {want!r}"
    # the two retained-away resources (dest1, conn1) are untouched by the stack's own delete
    _assert_destination(events, dest1, desc="second destination", conn_arn=out["ConnectionArn"],
                         endpoint=endpoint, method="PUT", rate=10, arn=out["DestinationArn"])
    _assert_connection(events, conn1, desc="second connection", auth_type="API_KEY",
                        label="sim2real-key-name", arn=out["ConnectionArn"])


def _assert_connection(events, name: str, *, desc: str, auth_type: str, label: str, arn: str) -> dict:
    conn = events.describe_connection(Name=name)
    got = (conn["Name"], conn["Description"], conn["AuthorizationType"], conn["ConnectionArn"])
    want = (name, desc, auth_type, arn)
    assert got == want, f"DescribeConnection {name!r}: {got!r}, expected {want!r}"
    auth_params = conn["AuthParameters"]
    if auth_type == "BASIC":
        got_label = auth_params["BasicAuthParameters"]["Username"]
    else:
        got_label = auth_params["ApiKeyAuthParameters"]["ApiKeyName"]
    assert got_label == label, f"DescribeConnection {name!r} auth label: {got_label!r}, expected {label!r}"
    return conn


def _assert_destination(events, name: str, *, desc: str, conn_arn: str, endpoint: str, method: str,
                         rate: int, arn: str) -> dict:
    dest = events.describe_api_destination(Name=name)
    got = (
        dest["Name"], dest["Description"], dest["ConnectionArn"], dest["InvocationEndpoint"],
        dest["HttpMethod"], dest["InvocationRateLimitPerSecond"], dest["ApiDestinationArn"],
    )
    want = (name, desc, conn_arn, endpoint, method, rate, arn)
    assert got == want, f"DescribeApiDestination {name!r}: {got!r}, expected {want!r}"
    state = _poll(
        None, lambda: events.describe_api_destination(Name=name)["ApiDestinationState"],
        lambda s: s in ("ACTIVE", "INACTIVE"), cap_s=30.0, what=f"destination {name} settled",
    )
    assert state == "ACTIVE", f"expected ApiDestinationState ACTIVE for {name!r}, got {state!r}"
    return dest


_CONNECTION_TERMINAL = frozenset({"AUTHORIZED", "DEAUTHORIZED", "ACTIVE", "FAILED_CONNECTIVITY"})


def _assert_connection_state(ctx, events, name: str, expected: str) -> None:
    state = _poll(
        ctx, lambda: events.describe_connection(Name=name)["ConnectionState"],
        lambda s: s in _CONNECTION_TERMINAL, cap_s=120.0, what=f"connection {name} settled",
    )
    assert state == expected, f"expected ConnectionState {expected!r} for {name!r}, got {state!r}"


def _delete_connection(events, name: str) -> None:
    try:
        events.delete_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_destination(events, name: str) -> None:
    try:
        events.delete_api_destination(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 3.0):
    """Call probe() until done(result) holds and return it; ctx=None (read helpers) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    return _poll(
        ctx, lambda: _stack(cfn, stack_id), lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_CAP_S, what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _outputs(stack: dict) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, body: str, params: list[dict]) -> list[dict]:
    """UpdateStack to body/params; assert UPDATE_COMPLETE; return every event the update added."""
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, Parameters=params)
    stack = _settle(ctx, cfn, stack_id)
    rows = _events(cfn, stack_id)[before:]
    failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
              for e in rows if e["ResourceStatus"].endswith("_FAILED")]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return rows


def _rows_for(rows: list[dict], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in rows if e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[dict], logical_id: str, physical: str) -> None:
    own = _rows_for(rows, logical_id)
    completed = [r for r in own if r[0] == "UPDATE_COMPLETE"]
    assert completed and completed[-1][2] == physical, (
        f"an in-place update of {logical_id} must complete on {physical!r}: {own!r}"
    )
    disruptive = [r for r in own if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert disruptive == [], f"an in-place update of {logical_id} must not replace it: {own!r}"


def _assert_replaced_and_retained(rows: list[dict], logical_id: str, old: str, new: str) -> None:
    own = _rows_for(rows, logical_id)
    reasons = [r[1] for r in own]
    assert _REPLACING in reasons, (
        f"the update of {logical_id} must report a replacement reason: {own!r}"
    )
    completed = [r for r in own if r[0] == "UPDATE_COMPLETE"]
    assert completed and completed[-1][2] == new, (
        f"the replacement of {logical_id} must complete on the new id {new!r}: {own!r}"
    )
    skipped = [r for r in own if r[0] == "DELETE_SKIPPED" and r[2] == old]
    assert skipped, f"UpdateReplacePolicy Retain must skip deleting the old {logical_id} {old!r}: {own!r}"
    deleted = [r for r in own if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing for {logical_id}: {own!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx, lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_CAP_S, what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by name and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None, lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_CAP_S, what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None, lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), cap_s=_STACK_CAP_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} teardown ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
