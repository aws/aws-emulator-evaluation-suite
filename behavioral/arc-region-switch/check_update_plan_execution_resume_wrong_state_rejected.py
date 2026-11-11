"""update-plan-execution-resume-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-plan-execution-resume-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePlanExecution action=resume on an execution pending manual approval returns 200 and changes
    neither the execution state nor the pending step's status; approving the step still succeeds."""
    arc = ctx.client("arc-region-switch")
    role_arn = _create_execution_role(ctx)
    region_a, region_b = _pick_regions(ctx)
    arc_b = ctx.client("arc-region-switch", region=region_b)
    arn = _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b)
    ctx.on_cleanup(lambda: _safe_delete(arc, arn))

    # CreatePlan is a control-plane write; StartPlanExecution reads the regional data plane, which
    # replicates the plan with lag, so wait for the plan to be visible there first.
    _poll_until(
        lambda: _get_plan_in_region_or_none(arc_b, arn),
        lambda r: r is not None,
        timeout_s=60,
    )

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
        f"expected the execution to reach pendingManualApproval before the wrong-state resume "
        f"is attempted, got {pending['executionState']!r}"
    )

    arc_b.update_plan_execution(planArn=arn, executionId=execution_id, action="resume")

    unchanged = arc_b.get_plan_execution(planArn=arn, executionId=execution_id)
    assert unchanged["executionState"] == "pendingManualApproval", (
        f"a resume issued against a pendingManualApproval execution must have no effect, "
        f"expected executionState to remain pendingManualApproval, got "
        f"{unchanged['executionState']!r}"
    )
    approve_step = next(s for s in unchanged["stepStates"] if s["name"] == "Approve")
    assert approve_step["status"] == "pendingApproval", (
        f"a resume issued against a pendingManualApproval execution must have no effect, "
        f"expected the Approve step to remain pendingApproval, got {approve_step['status']!r}"
    )

    # positive control: the execution is otherwise fully functional. Approving requires the
    # caller to BE the plan's configured approvalRole, so assume it for this one call.
    approver = _assume_role_client(ctx, role_arn, "arc-region-switch", region_b)
    approver.approve_plan_execution_step(
        planArn=arn, executionId=execution_id, stepName="Approve", approval="approve"
    )
    final = _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"]
        in ("completed", "completedWithExceptions", "failed", "canceled"),
        timeout_s=90,
    )
    assert final["executionState"] == "completed", (
        f"expected the execution to reach completed via the correct (approve) action after the "
        f"no-op resume, got {final['executionState']!r}"
    )


def _pick_regions(ctx):
    # region_b is the check's own region, where StartPlanExecution is called; region_a is the
    # plan's other (primary) region, used only as plan metadata and never called.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _safe_delete(arc, arn):
    try:
        arc.delete_plan(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_plan_in_region_or_none(arc, arn):
    from botocore.exceptions import ClientError

    try:
        return arc.get_plan_in_region(arn=arn)["plan"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
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
                # check assumes this role for the positive-control approve.
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    return arn


def _retry_on_propagation_lag(fn, what, attempts=8, delay_s=5.0):
    """IAM role trust-policy visibility to arc-region-switch is eventually consistent, not
    instantaneous even once get_role succeeds; retry the actual dependent call on denial instead
    of guessing a fixed settle time."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied", "IllegalArgumentException"):
                last_exc = e
                time.sleep(delay_s)
                continue
            raise
    raise AssertionError(
        f"{what} was persistently denied ({last_exc.response['Error']['Code']}) even for a "
        f"freshly created, correctly-trust-policied execution role after {attempts * delay_s:.0f}s "
        "of retries; this sandbox account appears to withhold arc-region-switch execution "
        "privileges (likely an iam:PassRole/service-principal allow-list gap for "
        "arc-region-switch.amazonaws.com) independent of the plan/role setup under test"
    ) from last_exc


def _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b, step_name="Approve"):
    arc = ctx.client("arc-region-switch")
    block = {
        "name": step_name,
        "executionBlockType": "ManualApproval",
        "executionBlockConfiguration": {
            "executionApprovalConfig": {"approvalRole": role_arn, "timeoutMinutes": 60}
        },
    }
    resp = _retry_on_propagation_lag(
        lambda: arc.create_plan(
            name=_plan_name(ctx),
            regions=[region_a, region_b],
            recoveryApproach="activePassive",
            primaryRegion=region_a,
            executionRole=role_arn,
            workflows=[
                {"workflowTargetAction": "activate", "steps": [block]},
            ],
            tags={"sim2real-check": CHECK},
        ),
        "CreatePlan",
    )
    return resp["plan"]["arn"]


def _start_execution_with_retry(arc, **kwargs):
    return _retry_on_propagation_lag(
        lambda: arc.start_plan_execution(**kwargs), "StartPlanExecution"
    )


def _assume_role_client(ctx, role_arn, service_name, region):
    sts = ctx.client("sts")

    def _assume():
        creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-arc-approve")[
            "Credentials"
        ]
        return ctx.client(
            service_name,
            region=region,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )

    return _retry_on_propagation_lag(_assume, "AssumeRole")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
