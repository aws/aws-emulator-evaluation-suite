"""eventbridge-input-transformer-output-is-sfn-execution-input."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-input-transformer-output-is-sfn-execution-input"

GROUP = "data-format"

SERVICES = ["events", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge target InputTransformer output becomes the Step Functions execution input
    exactly (whole-dict equality, raw envelope absent): a transformer honoured for Lambda/SQS but
    ignored for an SFN target would start the execution with the raw event."""
    events = ctx.client("events")
    ctx.client("stepfunctions")

    # A Pass state needs no permissions, so nothing but the transformer is under test; its
    # output equals its input, which lets the check prove the payload flowed through too.
    sm = _create_state_machine(
        ctx,
        definition={"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}},
        permissions=[],
    )

    bus_name = _xname(ctx, "bus")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = _xname(ctx, "rule")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(
            {"source": ["sim2real.xsvc"], "detail-type": ["OrderPlaced"]}
        ),
        State="ENABLED",
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )

    events_role = _create_role(
        ctx,
        "events.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "states:StartExecution",
                    "Resource": sm["arn"],
                }
            ],
        },
    )

    order_id = _xname(ctx, "order")
    # Every substituted value is a STRING so the template's JSON shape is unambiguous.
    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {
                "Id": "sfn-target",
                "Arn": sm["arn"],
                "RoleArn": events_role["arn"],
                "InputTransformer": {
                    "InputPathsMap": {
                        "oid": "$.detail.order_id",
                        "amt": "$.detail.amount",
                        "src": "$.source",
                        "dt": "$.detail-type",
                    },
                    "InputTemplate": json.dumps(
                        {
                            "orderId": "<oid>",
                            "amount": "<amt>",
                            "origin": "<src>",
                            "kind": "<dt>",
                            "constant": "not-from-the-event",
                        }
                    ),
                },
            }
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, EventBusName=bus_name, Ids=["sfn-target"]
        )
    )

    def _fire():
        resp = events.put_events(
            Entries=[
                {
                    "Source": "sim2real.xsvc",
                    "DetailType": "OrderPlaced",
                    "Detail": json.dumps({"order_id": order_id, "amount": "42"}),
                    "EventBusName": bus_name,
                }
            ]
        )
        assert resp.get("FailedEntryCount", 0) == 0, f"PutEvents rejected the event: {resp}"

    # 180s: rule + target propagation, re-fired each poll (extra executions are harmless).
    execution = _first_execution(ctx, sm["arn"], trigger=_fire, timeout_s=180, interval_s=5.0)
    desc = _wait_execution_terminal(ctx, execution["executionArn"], timeout_s=90)
    assert desc["status"] == "SUCCEEDED", (
        f"transformed execution did not succeed: {desc['status']} {desc.get('cause')}"
    )

    observed = json.loads(desc["input"])
    expected = {
        "orderId": order_id,
        "amount": "42",
        "origin": "sim2real.xsvc",
        "kind": "OrderPlaced",
        "constant": "not-from-the-event",
    }
    # Whole-dict equality: an extra key means the emulator merged the envelope in, a missing
    # key means it dropped a substitution, a different value means it substituted wrongly.
    assert observed == expected, (
        f"InputTransformer output is not the SFN execution input.\nexpected {expected}\n"
        f"got      {observed}"
    )
    # Effect-absent half: the raw bus envelope must NOT reach the target.
    for leaked in ("detail", "detail-type", "id", "resources", "version"):
        assert leaked not in observed, (
            f"raw EventBridge envelope field {leaked!r} leaked past the InputTransformer: {observed}"
        )
    # The transformed payload must also be what the state machine actually ran on.
    assert json.loads(desc["output"]) == expected, (
        f"Pass state output diverged from its input: {desc['output']!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


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


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion; a role already
    gone is fine, any other error raises."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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
    arn = _create_state_machine_with_retry(sfn, name, definition, role["arn"])
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, arn))
    return {"name": name, "arn": arn}


def _create_state_machine_with_retry(
    sfn, name, definition, role_arn, *, timeout_s=30.0, interval_s=3.0
):
    """CreateStateMachine assumes roleArn immediately, but a just-created IAM role is not always
    visible yet (trust/permission propagation), so a ClientError here is retried on a bounded
    deadline instead of via an unconditional pre-sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=_xsvc_tags_lower(),
            )["stateMachineArn"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _first_execution(ctx, sm_arn, *, trigger, timeout_s=180.0, interval_s=5.0):
    """Call trigger() each poll until the state machine has >=1 execution; return the first one.

    EventBridge/Pipes target wiring is not live the instant put_targets/create_pipe returns, so a
    single fire-and-wait races the control plane. Extra executions are harmless because the
    assertion reads one execution's input.
    """
    sfn = ctx.client("stepfunctions")

    def _probe():
        trigger()
        return sfn.list_executions(stateMachineArn=sm_arn, maxResults=5).get(
            "executions", []
        )

    execs = _poll_until(
        _probe,
        lambda e: len(e) > 0,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"execution of {sm_arn}",
    )
    return execs[0]


def _wait_execution_terminal(ctx, exec_arn, *, timeout_s=90.0):
    """Poll describe_execution until the execution reaches a terminal status; return the response."""
    sfn = ctx.client("stepfunctions")
    return _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"]
        in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"execution {exec_arn} terminal",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
