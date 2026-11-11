"""eventbridge-to-sfn-to-ddb-chain."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-to-sfn-to-ddb-chain"

GROUP = "event-chain"

SERVICES = ["dynamodb", "events", "stepfunctions"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge event -> Step Functions execution -> DynamoDB write."""
    table = _create_table(ctx)
    ddb = ctx.client("dynamodb")

    sm = _create_state_machine(
        ctx,
        definition={
            "StartAt": "WriteItem",
            "States": {
                "WriteItem": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::dynamodb:putItem",
                    "Parameters": {
                        "TableName": table["name"],
                        "Item": {
                            "pk": {"S.$": "$.detail.order_id"},
                            "status": {"S": "received"},
                            "source": {"S": "eventbridge-chain"},
                        },
                    },
                    "End": True,
                },
            },
        },
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
    )
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, sm["arn"]))

    events = ctx.client("events")
    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["sim2real.test"], "detail-type": ["OrderPlaced"]}
        ),
        State="ENABLED",
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, EventBusName=bus_name, Ids=["sfn-target"]
        )
    )

    iam = ctx.client("iam")
    role_name = ctx.unique_name("eb-sfn-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Path="/sim2real/"
    )
    role_arn = role_resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="start-sfn",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "states:StartExecution",
                        "Resource": sm["arn"],
                    },
                ],
            }
        ),
    )

    _put_targets_until_accepted(
        events,
        rule_name=rule_name,
        bus_name=bus_name,
        targets=[{"Id": "sfn-target", "Arn": sm["arn"], "RoleArn": role_arn}],
    )

    order_id = f"order-{uuid.uuid4().hex[:8]}"

    def _send_event():
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.test",
                    "DetailType": "OrderPlaced",
                    "Detail": json.dumps({"order_id": order_id}),
                    "EventBusName": bus_name,
                }
            ]
        )

    def _check_item():
        try:
            resp = ddb.get_item(TableName=table["name"], Key={"pk": {"S": order_id}})
            return resp.get("Item")
        except Exception:
            return None

    # A just-created target role that events.amazonaws.com cannot yet assume is a
    # PERMANENT AccessDenied to EventBridge, not a retryable one -- PutTargets accepted the
    # role without validating it (no condition to poll for propagation), so the target
    # was silently never invoked for the first PutEvents. Resending the identical event
    # (idempotent: the SFN Task always writes the same Item for this order_id) is what
    # bounds that race with a real retry instead of a longer blind wait.
    item = None
    deadline = time.monotonic() + 120
    attempts = 0
    next_send = 0.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send:
            attempts += 1
            _send_event()
            next_send = now + 15
        item = _check_item()
        if item is not None:
            break
        time.sleep(3)
    if item is None:
        raise AssertionError(
            f"no item appeared at pk={order_id!r} in {table['name']!r} after {attempts} "
            f"PutEvents attempt(s) over 120s; {_diagnose_sfn(ctx, sm['arn'])}"
        )
    assert item["status"]["S"] == "received", (
        f"expected status 'received', got {item['status']!r} -- the SFN Task did not write "
        "the literal Parameters this check's own state machine definition specifies"
    )
    assert item["source"]["S"] == "eventbridge-chain", (
        f"expected source 'eventbridge-chain', got {item['source']!r} -- the SFN Task did not "
        "write the literal Parameters this check's own state machine definition specifies"
    )


# ===== helpers =====
def _diagnose_sfn(ctx, sm_arn: str) -> str:
    """Attach the state machine's own executions to a timeout so a failed EventBridge
    delivery reads differently from a delivered-but-failing execution."""
    try:
        sfn = ctx.client("stepfunctions")
        execs = sfn.list_executions(stateMachineArn=sm_arn, maxResults=5).get(
            "executions", []
        )
        if not execs:
            return "no executions of the state machine were ever started"
        parts = []
        for e in execs:
            detail = sfn.describe_execution(executionArn=e["executionArn"])
            parts.append(
                f"{e['status']}"
                + (
                    f" ({detail.get('error')}: {detail.get('cause')})"
                    if detail.get("error")
                    else ""
                )
            )
        return f"{len(execs)} execution(s) started: {parts}"
    except Exception as exc:
        return f"could not inspect state machine executions: {exc!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _stop_and_delete_state_machine(ctx, arn: str) -> None:
    """Delete a Step Functions state machine and wait until it is gone.

    SFN deletion is asynchronous, and a state machine with a RUNNING execution lingers in
    DELETING, so running executions are stopped first. A state machine or execution already gone
    is fine; any other error, or the state machine still present after 90 s, raises.
    """
    sfn = ctx.client("stepfunctions")
    try:
        paginator = sfn.get_paginator("list_executions")
        for page in paginator.paginate(stateMachineArn=arn, statusFilter="RUNNING"):
            for ex in page.get("executions", []):
                try:
                    sfn.stop_execution(executionArn=ex["executionArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
                        raise
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    deadline = time.monotonic() + 90
    while True:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"state machine {arn} still present 90 s after DeleteStateMachine")
        time.sleep(2)


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xsvc_tags_lower() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _put_targets_until_accepted(
    events_client,
    *,
    rule_name: str,
    bus_name: str,
    targets: list,
    deadline_s: float = 60.0,
):
    """``PutTargets`` is a partial-failure API: it returns 200 even when EventBridge cannot
    yet assume a just-created target role, reporting the rejection only in
    ``FailedEntryCount``/``FailedEntries`` -- never as a raised error. Retrying on the
    response body (not on an exception) is the only way to bound the same IAM propagation
    race without waiting it out with a sleep."""
    deadline = time.monotonic() + deadline_s
    attempt = 0
    while True:
        resp = events_client.put_targets(
            Rule=rule_name, EventBusName=bus_name, Targets=targets
        )
        if resp.get("FailedEntryCount", 0) == 0:
            return resp
        failed = resp.get("FailedEntries", [])
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"put_targets kept rejecting the target(s) after {deadline_s}s: {failed}"
            )
        attempt += 1
        time.sleep(min(3.0, 0.5 + 0.5 * attempt))


def _retry_role_propagation(fn, *, deadline_s: float = 60.0):
    """Retry ``fn()`` while it fails on IAM role/policy propagation catching up -- there is
    no condition to poll for this (the trust/permission update is immediately visible to an
    IAM read; only the *other* service's cache of it lags), so the bound is a deadline on the
    real dependent call rather than a blind sleep. Any other error, or the deadline itself,
    raises."""
    deadline = time.monotonic() + deadline_s
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            msg = exc.response.get("Error", {}).get("Message", "")
            propagating = code in (
                "AccessDeniedException",
                "ValidationException",
                "InvalidParameterValueException",
            ) and (
                "assume" in msg.lower()
                or "not authorized" in msg.lower()
                or "cannot be assumed" in msg.lower()
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            attempt += 1
            time.sleep(min(3.0, 0.5 + 0.5 * attempt))


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_table(
    ctx,
    key_schema=None,
    attributes=None,
    stream=False,
    stream_view_type="NEW_AND_OLD_IMAGES",
) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn[,stream_arn]}."""
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    params: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema or [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": attributes
        or [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": _xsvc_tags_kv(),
    }
    if stream:
        params["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream_view_type,
        }
    resp = ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    result = {"name": name, "arn": resp["TableDescription"]["TableArn"]}
    if stream:
        result["stream_arn"] = resp["TableDescription"].get("LatestStreamArn", "")
    return result


def _create_state_machine(ctx, definition, permissions=None) -> dict[str, str]:
    """Create a Step Functions state machine with an execution role (permissions=None → full
    access; [] → empty policy, for denial tests). Role + SM register their own teardown.
    Returns {name,arn}."""
    if permissions is None:
        statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    elif permissions:
        statements = [
            {"Effect": "Allow", "Action": p["Action"], "Resource": p["Resource"]}
            for p in permissions
        ]
    else:
        statements = []
    policy = {"Version": "2012-10-17", "Statement": statements} if statements else None
    role = _create_role(ctx, "states.amazonaws.com", inline_policy=policy)
    name = _xname(ctx, "sm")
    sfn = ctx.client("stepfunctions")
    arn = _retry_role_propagation(
        lambda: sfn.create_state_machine(
            name=name,
            definition=json.dumps(definition),
            roleArn=role["arn"],
            type="STANDARD",
            tags=_xsvc_tags_lower(),
        )
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
