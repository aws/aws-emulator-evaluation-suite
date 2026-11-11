"""start-plan-execution-manual-approval-completes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-plan-execution-manual-approval-completes"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A plan execution with a manual-approval step moves pending, pendingManualApproval, completed,
    with the step status tracking it, a chronological ListPlanExecutionEvents stream, and
    ListPlanExecutions' state filter reflecting the final state."""
    ctx.client("arc-region-switch")
    account_id = _account_id(ctx)
    role_arn = _create_execution_role(ctx, account_id)
    region_a, region_b = _pick_regions(ctx)
    arc_b = ctx.client("arc-region-switch", region=region_b)
    arn = _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b, account_id)

    start_resp = _start_execution_with_retry(
        arc_b, planArn=arn, targetRegion=region_b, action="activate"
    )
    execution_id = start_resp["executionId"]

    pending = _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"] != "pending",
        timeout_s=90,
    )
    assert pending["executionState"] == "pendingManualApproval", (
        f"expected pendingManualApproval, got {pending['executionState']!r}"
    )
    assert len(pending["stepStates"]) == 1, f"expected 1 step, got {pending['stepStates']!r}"
    assert pending["stepStates"][0]["name"] == "Approve", (
        f"expected step name Approve, got {pending['stepStates'][0]['name']!r}"
    )
    assert pending["stepStates"][0]["status"] == "pendingApproval", (
        f"expected step status pendingApproval, got {pending['stepStates'][0]['status']!r}"
    )

    approver_creds = _assume_role_with_retry(
        ctx.client("sts"), role_arn, ctx.unique_name("sim2real-approver-")
    )
    arc_approver = ctx.client("arc-region-switch", region=region_b, creds=approver_creds)
    arc_approver.approve_plan_execution_step(
        planArn=arn, executionId=execution_id, stepName="Approve", approval="approve"
    )

    final = _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"]
        in ("completed", "completedWithExceptions", "failed", "canceled"),
        timeout_s=90,
    )
    assert final["executionState"] == "completed", (
        f"expected completed, got {final['executionState']!r}"
    )
    assert final["stepStates"][0]["status"] == "completed", (
        f"expected step status completed, got {final['stepStates'][0]['status']!r}"
    )
    assert final["executionAction"] == "activate", (
        f"expected executionAction activate, got {final['executionAction']!r}"
    )
    assert final["executionRegion"] == region_b, (
        f"expected executionRegion {region_b!r}, got {final['executionRegion']!r}"
    )
    assert final["mode"] == "graceful", f"expected mode graceful, got {final['mode']!r}"

    events = arc_b.list_plan_execution_events(planArn=arn, executionId=execution_id)["items"]
    assert len(events) > 0, f"expected at least one execution event, got {events!r}"
    event_types = [e["type"] for e in events]
    assert "executionStarted" in event_types, f"executionStarted missing from {event_types!r}"
    assert "executionSucceeded" in event_types, f"executionSucceeded missing from {event_types!r}"
    # Each event carries its own `timestamp`; the list's ITEM ORDER is not documented as
    # chronological (list APIs on this service commonly return newest-first), so the ordering
    # claim is checked against the target's own reported timestamps, not list position.
    started_ts = next(e["timestamp"] for e in events if e["type"] == "executionStarted")
    succeeded_ts = next(e["timestamp"] for e in events if e["type"] == "executionSucceeded")
    assert started_ts <= succeeded_ts, (
        f"executionStarted ({started_ts}) did not precede executionSucceeded ({succeeded_ts})"
    )

    completed_list = arc_b.list_plan_executions(planArn=arn, state="completed")["items"]
    assert any(item["executionId"] == execution_id for item in completed_list), (
        f"{execution_id} missing from completed executions {completed_list!r}"
    )
    in_progress_list = arc_b.list_plan_executions(planArn=arn, state="inProgress")["items"]
    assert all(item["executionId"] != execution_id for item in in_progress_list), (
        f"{execution_id} unexpectedly present in inProgress executions {in_progress_list!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _pick_regions(ctx):
    # region_b is the check's own region, where StartPlanExecution is called; region_a is the
    # plan's other (primary) region, used only as plan metadata and never called.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=40.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return {
                "aws_access_key_id": resp["Credentials"]["AccessKeyId"],
                "aws_secret_access_key": resp["Credentials"]["SecretAccessKey"],
                "aws_session_token": resp["Credentials"]["SessionToken"],
            }
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_execution_role(ctx, account_id):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-arcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "arc-region-switch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                # ApprovePlanExecutionStep requires the caller to be the plan's approvalRole (any
                # other identity gets "Role ... is not allowed to approve this execution"), so the
                # check assumes this role to approve.
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real-check", "Value": CHECK},
            {"Key": "sim2real-account", "Value": account_id},
        ],
    )["Role"]
    arn = role["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-all",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="allow-all")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for _ in range(20):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(1)
    # IAM->arc-region-switch trust propagation has no observable side-channel from here; the
    # retry loop in _start_execution_with_retry (below) is what actually absorbs that delay.
    return arn


def _create_plan_with_approval_workflow(
    ctx, role_arn, region_a, region_b, account_id, step_name="Approve"
):
    arc = ctx.client("arc-region-switch")
    block = {
        "name": step_name,
        "executionBlockType": "ManualApproval",
        "executionBlockConfiguration": {
            "executionApprovalConfig": {"approvalRole": role_arn, "timeoutMinutes": 60}
        },
    }
    resp = arc.create_plan(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[
            {"workflowTargetAction": "activate", "steps": [block]},
        ],
        tags={"sim2real-check": CHECK, "sim2real-account": account_id},
    )
    arn = resp["plan"]["arn"]
    ctx.on_cleanup(lambda: arc.delete_plan(arn=arn))
    return arn


def _start_execution_with_retry(arc, **kwargs):
    from botocore.exceptions import ClientError

    # CreatePlan/GetPlan are control-plane operations; StartPlanExecution is regional data-plane
    # (the Smithy model's staticContextParams: only the former pair sets
    # UseControlPlaneEndpoint). A plan just created can 404 here for a few seconds while it
    # replicates from the control plane to the region -- that is ResourceNotFoundException, not
    # a missing plan. AccessDeniedException/IllegalArgumentException absorb IAM-role and
    # cross-service trust-policy propagation the same way.
    last_exc = None
    for _ in range(8):
        try:
            return arc.start_plan_execution(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "IllegalArgumentException", "ResourceNotFoundException"):
                last_exc = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        f"StartPlanExecution did not succeed within 40s of retries for planArn="
        f"{kwargs.get('planArn')!r}; last error: "
        f"{last_exc.response['Error']['Code']}: {last_exc.response['Error'].get('Message')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
