"""active-execution-blocks-start-and-delete-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "active-execution-blocks-start-and-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a plan execution is active, StartPlanExecution and DeletePlan fail IllegalStateException
    and leave the plan and its execution untouched; both succeed once the execution is terminal."""
    arc = ctx.client("arc-region-switch")
    role_arn = _create_execution_role(ctx)
    approval_role_arn = _create_approval_role(ctx, role_arn.split(":")[4])
    region_a, region_b = _pick_regions(ctx)
    arc_b = ctx.client("arc-region-switch", region=region_b)
    approver = _assumed_role_client(ctx, approval_role_arn, region_b)
    arn = _create_plan_with_approval_workflow(ctx, role_arn, approval_role_arn, region_a, region_b)

    def _cleanup_plan():
        # A plan with an active execution refuses DeletePlan, so cancel what is still running.
        for item in arc.list_plan_executions(planArn=arn)["items"]:
            if item["executionState"] not in _TERMINAL:
                arc_b.cancel_plan_execution(planArn=arn, executionId=item["executionId"])
                _poll_until(
                    lambda eid=item["executionId"]: arc_b.get_plan_execution(planArn=arn, executionId=eid),
                    lambda r: r["executionState"] in _TERMINAL,
                    timeout_s=120,
                )
        # DeletePlan can still see the just-ended execution as active: retry that refusal every 2 s.
        deadline = time.monotonic() + _CLEANUP_BUDGET_S
        while True:
            try:
                arc.delete_plan(arn=arn)
                return
            except arc.exceptions.ResourceNotFoundException:
                return
            except arc.exceptions.IllegalStateException:
                if time.monotonic() >= deadline:
                    raise
            time.sleep(2.0)

    ctx.on_cleanup(_cleanup_plan)

    first = _start_execution_with_retry(arc_b, planArn=arn, targetRegion=region_b, action="activate")
    execution_id = first["executionId"]

    _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"] != "pending",
        timeout_s=90,
    )

    # negative 1: a second execution cannot start while the first is active
    got1 = _error(
        lambda: arc_b.start_plan_execution(planArn=arn, targetRegion=region_b, action="activate")
    )
    assert got1 == ("IllegalStateException", f"There is already an execution ongoing for plan {arn}"), got1
    executions = arc.list_plan_executions(planArn=arn)["items"]
    assert len(executions) == 1
    assert executions[0]["executionId"] == execution_id

    # negative 2: the plan cannot be deleted while it has an active execution
    got2 = _error(lambda: arc.delete_plan(arn=arn))
    # executionId reads "<region>/<id>"; the message lists the same pair as "<region>: <id>".
    exec_region, exec_suffix = execution_id.split("/", 1)
    active_msg = f"Active executions found for {arn}: {exec_region}: {exec_suffix}"
    assert got2 == ("IllegalStateException", active_msg), got2
    assert arc.get_plan(arn=arn)["plan"]["arn"] == arn

    # positive control: once the execution reaches a terminal state, both operations succeed
    approver.approve_plan_execution_step(
        planArn=arn, executionId=execution_id, stepName="Approve", approval="approve"
    )
    _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"] in _TERMINAL,
        timeout_s=90,
    )
    second = arc_b.start_plan_execution(planArn=arn, targetRegion=region_b, action="activate")
    assert "executionId" in second
    _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=second["executionId"]),
        lambda r: r["executionState"] != "pending",
        timeout_s=90,
    )
    approver.approve_plan_execution_step(
        planArn=arn, executionId=second["executionId"], stepName="Approve", approval="approve"
    )
    _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=second["executionId"]),
        lambda r: r["executionState"] in _TERMINAL,
        timeout_s=90,
    )
    arc.delete_plan(arn=arn)
    gone = _error(lambda: arc.get_plan(arn=arn))
    assert gone == ("ResourceNotFoundException", f"Plan not found for ARN: {arn}"), gone


_TERMINAL = ("completed", "completedWithExceptions", "failed", "canceled")

#: Seconds the check's teardowns may spend retrying a refusal.
_CLEANUP_BUDGET_S = 900.0


def _pick_regions(ctx):
    # region_b is the check's own region, where StartPlanExecution is called; region_a is the
    # plan's other (primary) region, used only as plan metadata and never called.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a rejection, call unexpectedly succeeded")


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
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "arc-region-switch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_plan_with_approval_workflow(
    ctx, role_arn, approval_role_arn, region_a, region_b, step_name="Approve"
):
    arc = ctx.client("arc-region-switch")
    block = {
        "name": step_name,
        "executionBlockType": "ManualApproval",
        "executionBlockConfiguration": {
            "executionApprovalConfig": {"approvalRole": approval_role_arn, "timeoutMinutes": 60}
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
        tags={"sim2real": CHECK},
    )
    return resp["plan"]["arn"]


def _create_approval_role(ctx, account):
    # ApprovePlanExecutionStep authorizes by caller identity against `approvalRole` (real AWS
    # rejects a caller that is not the role with "Role ... is not allowed to approve this
    # execution"), so the approver ASSUMES this role -- distinct from the execution role, whose
    # trust policy grants only the service principal. The trust names the account (taken from
    # the execution role this check created), not the caller's own identity.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-arcapprove-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _assumed_role_client(ctx, role_arn, region):
    sts = ctx.client("sts")
    session_name = ctx.unique_name("sim2real-approve-")[:64]

    def _try_assume():
        return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]

    from botocore.exceptions import ClientError

    creds = None
    for _ in range(20):
        try:
            creds = _try_assume()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                time.sleep(1)
                continue
            raise
    if creds is None:
        raise AssertionError(
            f"could not assume freshly created approval role {role_arn} within 20s of retries"
        )

    return ctx.client(
        "arc-region-switch",
        region=region,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _start_execution_with_retry(arc, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(8):
        try:
            return arc.start_plan_execution(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "IllegalArgumentException", "ResourceNotFoundException"):
                # ResourceNotFoundException: a freshly created plan reaches StartPlanExecution's
                # regional data plane after a second or two.
                last_exc = e
                time.sleep(5)
                continue
            raise
    if isinstance(last_exc, ClientError) and last_exc.response["Error"]["Code"] == "AccessDeniedException":

        raise AssertionError(
            "StartPlanExecution was persistently denied (AccessDeniedException with no detail) "
            "even for a freshly created, correctly-trust-policied execution role after 40s of "
            "retries; the account appears to withhold arc-region-switch execution "
            "privileges (likely an iam:PassRole/service-principal allow-list gap for "
            "arc-region-switch.amazonaws.com) independent of the plan/role setup under test"
        )
    if isinstance(last_exc, ClientError) and last_exc.response["Error"]["Code"] == "ResourceNotFoundException":
        raise AssertionError(
            f"StartPlanExecution still reports the plan not found after 40s of retries: "
            f"{last_exc.response['Error'].get('Message')}"
        )
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
