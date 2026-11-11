"""sfn-no-permission-to-write-ddb."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-no-permission-to-write-ddb"

GROUP = "overly-permissive"

SERVICES = ["dynamodb", "iam", "stepfunctions"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SFN execution with a role that lacks dynamodb:PutItem must FAIL, with the effect absent at
    the table; restoring the identical permission must let the identical call then succeed."""
    table = _create_table(ctx)
    ddb = ctx.client("dynamodb")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    write_action = "dynamodb:PutItem"

    def _policy(statements):
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    role = _create_role(
        ctx,
        "states.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": write_action, "Resource": table["arn"]}
            ],
        },
    )
    sm_name = _xname(ctx, "sm")
    definition = {
        "StartAt": "Write",
        "States": {
            "Write": {
                "Type": "Task",
                "Resource": "arn:aws:states:::dynamodb:putItem",
                "Parameters": {
                    "TableName": table["name"],
                    "Item": {"pk": {"S.$": "$.pk"}},
                },
                "End": True,
            },
        },
    }
    # A just-created role is not yet assumable by Step Functions: retried on that refusal to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (90 if left is None else min(90, left))
    while True:
        try:
            sm_arn = sfn.create_state_machine(
                name=sm_name,
                definition=json.dumps(definition),
                roleArn=role["arn"],
                type="STANDARD",
                tags=_xsvc_tags_lower(),
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if ("not authorized to assume" not in str(exc)
                    and "assume the provided role" not in str(exc)) or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: _stop_and_delete_state_machine(ctx, sm_arn))

    def _run(pk: str) -> tuple[str, dict]:
        execution = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"pk": pk})
        )
        exec_arn = execution["executionArn"]
        desc = _wait_for_effect(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=30,
        )
        return exec_arn, desc

    def _run_until(
        pk: str, expect_status: str, timeout_s: float = 90.0
    ) -> tuple[str, dict]:
        """Retry the execution through an IAM propagation window (never an unconditional sleep) —
        a just-changed policy can transiently still reflect the old grant. Safe to reuse `pk`
        across attempts here because every retry is *seeking* a success — an attempt that does
        not (yet) reach it leaves no side effect under that key."""
        deadline = time.monotonic() + timeout_s
        while True:
            exec_arn, desc = _run(pk)
            if desc["status"] == expect_status:
                return exec_arn, desc
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"Execution for pk={pk!r} never reached {expect_status} within {timeout_s}s "
                    f"of IAM propagation; last status {desc['status']}"
                )
            time.sleep(5)

    def _run_until_failed(timeout_s: float = 90.0) -> tuple[str, str, dict]:
        """Retry with a FRESH pk on every attempt. Unlike `_run_until`, a retry here is seeking a
        *denial* — a premature attempt that still succeeds (the just-revoked policy has not
        propagated yet) writes a real item, and reusing one pk across attempts would let that
        stray write outlive the later, genuinely-denied attempt we report. Returns the pk of the
        attempt that actually failed, so the effect-absent check below is unambiguous."""
        deadline = time.monotonic() + timeout_s
        attempt = 0
        while True:
            attempt += 1
            pk = f"should-fail-{attempt}"
            exec_arn, desc = _run(pk)
            if desc["status"] == "FAILED":
                return pk, exec_arn, desc
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"Revoked dynamodb:PutItem never took effect within {timeout_s}s; "
                    f"last status {desc['status']} (pk={pk!r})"
                )
            time.sleep(5)

    def _item_present(pk: str) -> bool:
        return "Item" in ddb.get_item(
            TableName=table["name"], Key={"pk": {"S": pk}}, ConsistentRead=True
        )

    # 1. Positive control: with dynamodb:PutItem granted, the write succeeds and is visible.
    _, desc = _run_until("control", "SUCCEEDED")
    assert desc["status"] == "SUCCEEDED", (
        f"Positive control expected SUCCEEDED with dynamodb:PutItem granted, got {desc['status']}"
    )
    assert _item_present("control"), (
        "Positive control item missing at the table despite a SUCCEEDED execution"
    )

    # 2. Break exactly one thing: revoke the write permission. IAM rejects an inline policy with
    # an empty Statement list (MalformedPolicyDocument), so the revoke is a delete, not a put.
    iam.delete_role_policy(RoleName=role["name"], PolicyName="inline")

    # 3. Negative: the identical shape of call, denied.
    pk_neg, exec_arn, desc = _run_until_failed()
    assert desc["status"] == "FAILED", (
        f"Expected FAILED with dynamodb:PutItem revoked, got {desc['status']}"
    )

    # 4. The specific error, not a generic FAILED.
    history = sfn.get_execution_history(executionArn=exec_arn, reverseOrder=True)[
        "events"
    ]
    failed = next(e for e in history if e["type"] == "TaskFailed")
    details = failed["taskFailedEventDetails"]
    assert "DynamoDB" in details["error"] and (
        "AccessDenied" in details["error"] or "AccessDenied" in details.get("cause", "")
    ), (
        f"Expected a DynamoDB access-denied task failure, got error={details['error']!r} "
        f"cause={details.get('cause')!r}"
    )

    # 5. Effect absent at the destination, independent of the SFN status word.
    assert not _item_present(pk_neg), (
        "Item present at the table despite the execution reporting FAILED"
    )

    # 6. Restore the identical permission.
    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName="inline",
        PolicyDocument=_policy(
            [{"Effect": "Allow", "Action": write_action, "Resource": table["arn"]}]
        ),
    )

    # 7. The identical call (same pk, same everything) now succeeds.
    _run_until(pk_neg, "SUCCEEDED")
    assert _item_present(pk_neg), (
        "Item still missing after the restored, identical call reported SUCCEEDED"
    )


# ===== helpers =====
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
