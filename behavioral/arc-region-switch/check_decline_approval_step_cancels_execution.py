"""decline-approval-step-cancels-execution."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "decline-approval-step-cancels-execution"
GROUP = "state"
SERVICES = ["arc-region-switch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Declining a manual-approval step cancels the whole plan execution (documented behavior)."""
    ctx.client("arc-region-switch")
    role_arn = _create_execution_role(ctx)
    region_a, region_b = _pick_regions(ctx)
    arc_b = _regional_client(ctx, region_b)
    arn = _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b)

    # CreatePlan writes the control plane; StartPlanExecution reads the regional data plane, which
    # replicates the plan with lag. Bound the wait on that specific, observable condition instead of
    # a blind sleep.
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
        f"expected pendingManualApproval after start, got {pending['executionState']!r}"
    )
    assert pending["stepStates"][0]["name"] == "Approve", (
        f"expected the 'Approve' step to be pending, got {pending['stepStates'][0]!r}"
    )
    assert pending["stepStates"][0]["status"] == "pendingApproval", (
        f"expected step status pendingApproval, got {pending['stepStates'][0]['status']!r}"
    )

    approver_arc = _assume_approval_role(ctx, role_arn, region_b)
    approver_arc.approve_plan_execution_step(
        planArn=arn, executionId=execution_id, stepName="Approve", approval="decline"
    )

    final = _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"]
        in ("completed", "completedWithExceptions", "failed", "canceled"),
        timeout_s=90,
    )
    assert final["executionState"] == "canceled", (
        f"declining the approval step must cancel the whole execution, got {final['executionState']!r}"
    )
    assert final["stepStates"][0]["status"] == "failed", (
        f"expected the declined step's own status to read failed, got {final['stepStates'][0]['status']!r}"
    )


def _regional_client(ctx, region):
    return ctx.client("arc-region-switch", region=region)


def _assume_approval_role(ctx, role_arn, region):
    # ApprovePlanExecutionStep requires the caller to actually be the configured approvalRole,
    # not merely the account that created it -- assume it, bounded and retried for the trust
    # policy's own propagation lag, then sign the approval call with those credentials.
    from botocore.exceptions import ClientError

    sts = ctx.client("sts")
    last_exc = None
    for _ in range(10):
        try:
            resp = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-approve-")
            )
            break
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    else:
        raise AssertionError(f"could not assume approval role {role_arn} within retry budget: {last_exc}")
    creds = resp["Credentials"]
    return ctx.client(
        "arc-region-switch",
        region=region,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _get_plan_in_region_or_none(arc, arn):
    from botocore.exceptions import ClientError

    try:
        return arc.get_plan_in_region(arn=arn)["plan"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _pick_regions(ctx):
    # region_b is ctx.region, the region StartPlanExecution is called against; region_a is the
    # plan's other participating (primary) region, used only as metadata -- never dialed directly.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


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
    role_name = ctx.unique_name("sim2real-arcrole-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "arc-region-switch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                # ApprovePlanExecutionStep authorizes the caller against this same role
                # (real AWS: "Role <caller> is not allowed to approve this execution"), so the
                # check's own identity must also be able to assume it to act as the approver.
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b, step_name="Approve"):
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
        tags={"sim2real:managed": "true"},
    )
    arn = resp["plan"]["arn"]
    ctx.on_cleanup(lambda: _delete_plan_with_retry(arc, arn))
    return arn


def _delete_plan_with_retry(arc, arn, timeout_s=45.0, interval_s=3.0):
    # DeletePlan rejects with IllegalStateException for a short window after an execution
    # reaches a terminal state (the same replication lag GetPlanInRegion exposes elsewhere in
    # this service) -- a bare delete_plan() observed this leaking the plan past cleanup.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            arc.delete_plan(arn=arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "IllegalStateException":
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"could not delete plan {arn} within {timeout_s}s: {last_exc}")


def _start_execution_with_retry(arc, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(8):
        try:
            return arc.start_plan_execution(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "IllegalArgumentException"):
                last_exc = e
                time.sleep(5)
                continue
            raise
    if isinstance(last_exc, ClientError) and last_exc.response["Error"]["Code"] == "AccessDeniedException":

        raise AssertionError(
            "StartPlanExecution was persistently denied (AccessDeniedException with no detail) "
            "even for a freshly created, correctly-trust-policied execution role after 40s of "
            "retries; this sandbox account appears to withhold arc-region-switch execution "
            "privileges (likely an iam:PassRole/service-principal allow-list gap for "
            "arc-region-switch.amazonaws.com) independent of the plan/role setup under test"
        )
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
