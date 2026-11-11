"""missing-permission-start-plan-execution-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "missing-permission-start-plan-execution-denied"
GROUP = "overly-permissive"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller assuming an IAM role with no attached policies is denied StartPlanExecution with
    AccessDeniedException, no execution is created, and the same call succeeds for the
    original (permitted) caller (in-file positive control)."""
    arc = ctx.client("arc-region-switch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    exec_role_arn = _create_execution_role(ctx)
    # approvalRole must be an IAM ROLE ARN that the approving caller actually assumes (a plain
    # user/caller ARN is rejected at create_plan with "Invalid ARN format", and exec_role_arn's
    # own trust policy allows only the arc-region-switch service principal to assume it -- never
    # a human/test caller). So a second role, trusted by this account's root, stands in for the
    # human approver and gets assumed just before ApprovePlanExecutionStep.
    approver_role_arn = _create_approver_role(ctx, account_id)
    region_a, region_b = _pick_regions(ctx)
    arn = _create_plan_with_approval_workflow(
        ctx, exec_role_arn, approver_role_arn, region_a, region_b
    )
    ctx.on_cleanup(lambda: _delete_plan_when_idle(arc, arn))

    restricted_role_name = ctx.unique_name("sim2real-arc-noaccess-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    restricted_role_arn = iam.create_role(
        RoleName=restricted_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, restricted_role_name))
    _poll_until(lambda: _try_get_role(iam, restricted_role_name), lambda ok: ok, timeout_s=30)
    # _assume_role_with_retry's own retry budget (10 attempts, 3s apart) is the bounded wait for
    # trust-policy propagation -- a blind pre-sleep here would be an unstated, unbounded duplicate.
    creds = _assume_role_with_retry(sts, restricted_role_arn, "sim2real-behav-session")
    restricted_arc = ctx.client(
        "arc-region-switch",
        region=region_b,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    # region_b == ctx.region (see _pick_regions), so this is the SAME target-wired client as
    # `arc` -- reuse it rather than hand-rolling a second one that would bypass the emulator
    # endpoint entirely.
    arc_b = arc

    # positive control FIRST: confirm the permitted caller can start an execution at all in this
    # account before asserting anything about the restricted caller -- if StartPlanExecution is
    # persistently denied even for the fully-permitted role, that's an environment limitation
    # (see _start_execution_with_retry), not evidence this specific negative boundary holds.
    started = _start_execution_with_retry(arc_b, planArn=arn, targetRegion=region_b, action="activate")
    assert "executionId" in started
    executions = arc.list_plan_executions(planArn=arn)["items"]
    assert any(item["executionId"] == started["executionId"] for item in executions)

    code, message = _error(
        lambda: restricted_arc.start_plan_execution(
            planArn=arn, targetRegion=region_b, action="activate"
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for the policy-less caller, got {code!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{restricted_role_name}/"
        "sim2real-behav-session is not authorized to perform: "
        f"arc-region-switch:StartPlanExecution on resource: {arn} because no "
        "identity-based policy allows the arc-region-switch:StartPlanExecution action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # the restricted caller's rejected attempt created no additional execution
    assert len(arc.list_plan_executions(planArn=arn)["items"]) == 1

    # the manual-approval step isn't pending the instant start_plan_execution returns --
    # execution begins in "pending" and transitions asynchronously to "pendingManualApproval".
    # ApprovePlanExecutionStep before that transition 404s with ResourceNotFoundException.
    pending = _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=started["executionId"]),
        lambda r: r["executionState"] != "pending",
        timeout_s=60,
    )
    assert pending["executionState"] == "pendingManualApproval"
    assert pending["stepStates"][0]["status"] == "pendingApproval"

    approver_creds = _assume_role_with_retry(sts, approver_role_arn, "sim2real-approver-session")
    approver_arc = ctx.client(
        "arc-region-switch",
        region=region_b,
        creds={
            "aws_access_key_id": approver_creds["AccessKeyId"],
            "aws_secret_access_key": approver_creds["SecretAccessKey"],
            "aws_session_token": approver_creds["SessionToken"],
        },
    )
    approver_arc.approve_plan_execution_step(
        planArn=arn, executionId=started["executionId"], stepName="Approve", approval="approve"
    )
    _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=started["executionId"]),
        lambda r: r["executionState"]
        in ("completed", "completedWithExceptions", "failed", "canceled"),
        timeout_s=90,
    )


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
            "even for the fully-permitted caller after 40s of retries; this sandbox account "
            "appears to withhold arc-region-switch execution privileges (likely an "
            "iam:PassRole/service-principal allow-list gap for arc-region-switch.amazonaws.com) "
            "independent of the specific-caller boundary under test"
        )
    raise last_exc


def _pick_regions(ctx):
    # region_b is ctx.region, the region StartPlanExecution is called against; region_a is the
    # plan's other participating (primary) region, used only as metadata -- never dialed directly.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


_TERMINAL = ("completed", "completedWithExceptions", "failed", "canceled")


def _delete_plan_when_idle(arc, arn, timeout_s=180.0, interval_s=5.0):
    """Teardown: DeletePlan refuses with IllegalStateException while an execution is active, so
    cancel any active execution and retry until the plan is gone or the deadline passes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            arc.delete_plan(arn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "IllegalStateException" or time.monotonic() > deadline:
                raise
        for item in arc.list_plan_executions(planArn=arn).get("items", []):
            if item.get("executionState") not in _TERMINAL:
                try:
                    arc.cancel_plan_execution(planArn=arn, executionId=item["executionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        time.sleep(interval_s)


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _try_get_role(iam, role_name):
    try:
        iam.get_role(RoleName=role_name)
        return True
    except Exception:
        return False


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _assume_role_with_retry(sts, role_arn, session_name):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(10):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError:
            last_exc = ClientError
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} within retry budget: {last_exc}")


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
    _poll_until(lambda: _try_get_role(iam, role_name), lambda ok: ok, timeout_s=20, interval_s=1)
    return arn


def _create_approver_role(ctx, account_id):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-arc-approver-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
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
    _poll_until(lambda: _try_get_role(iam, role_name), lambda ok: ok, timeout_s=20, interval_s=1)
    return arn


def _create_plan_with_approval_workflow(
    ctx, role_arn, approval_role_arn, region_a, region_b, step_name="Approve"
):
    from botocore.exceptions import ClientError

    arc = ctx.client("arc-region-switch")
    block = {
        "name": step_name,
        "executionBlockType": "ManualApproval",
        "executionBlockConfiguration": {
            "executionApprovalConfig": {"approvalRole": approval_role_arn, "timeoutMinutes": 60}
        },
    }
    kwargs = dict(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[
            {"workflowTargetAction": "activate", "steps": [block]},
        ],
    )
    # The execution role's trust/inline policy was just created; arc-region-switch may not be
    # able to validate it as assumable yet. Bounded retry on the same codes
    # `_start_execution_with_retry` retries, rather than a blind pre-sleep with no stated
    # deadline.
    last_exc = None
    for _ in range(6):
        try:
            resp = arc.create_plan(**kwargs)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "IllegalArgumentException"):
                last_exc = e
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"create_plan with a fresh execution role never became valid: {last_exc}")
    return resp["plan"]["arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
