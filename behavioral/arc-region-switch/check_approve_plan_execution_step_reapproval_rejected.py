"""approve-plan-execution-step-reapproval-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "approve-plan-execution-step-reapproval-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Approving a manual-approval step succeeds exactly once; re-approving the same, now
    completed, step is rejected with ResourceNotFoundException and does not alter the
    already-completed state."""
    arc = ctx.client("arc-region-switch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_execution_role(ctx)
    approval_role_arn = _create_approval_role(ctx, account_id)
    region_a, region_b = _pick_regions(ctx)
    arc_b = _regional_client(ctx, region_b)
    arn = _create_plan_with_approval_workflow(ctx, role_arn, approval_role_arn, region_a, region_b)
    ctx.on_cleanup(lambda: _delete_plan_when_idle(arc, arn))

    start_resp = _start_execution_with_retry(
        arc_b, planArn=arn, targetRegion=region_b, action="activate"
    )
    execution_id = start_resp["executionId"]

    _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"] != "pending",
        timeout_s=90,
    )

    # ApprovePlanExecutionStep requires the CALLER to be the plan's configured approvalRole
    # (real AWS rejects the plan-owning account's own admin identity with AccessDeniedException:
    # "... is not allowed to approve this execution"), so approve as that assumed role, not as
    # whoever created the plan.
    arc_approver = _assume_role_client(ctx, region_b, approval_role_arn)

    # positive control: the first, valid approval succeeds. A freshly minted STS session can
    # briefly fail signature validation elsewhere in the account (observed:
    # UnrecognizedClientException/InvalidClientTokenId) before it propagates -- bounded retry,
    # not a sleep.
    _call_with_retry(
        lambda: arc_approver.approve_plan_execution_step(
            planArn=arn, executionId=execution_id, stepName="Approve", approval="approve"
        ),
        retryable_codes=("UnrecognizedClientException", "InvalidClientTokenId"),
    )
    completed = _poll_until(
        lambda: arc_b.get_plan_execution(planArn=arn, executionId=execution_id),
        lambda r: r["executionState"]
        in ("completed", "completedWithExceptions", "failed", "canceled"),
        timeout_s=90,
    )
    assert completed["executionState"] == "completed", (
        f"expected executionState=='completed' after the sole approval, got "
        f"{completed['executionState']!r}"
    )
    assert completed["stepStates"][0]["status"] == "completed", (
        f"expected stepStates[0].status=='completed' after the sole approval, got "
        f"{completed['stepStates'][0]['status']!r}"
    )

    # negative: approving the same step again is rejected, no double-processing
    code, message = _error(
        lambda: arc_approver.approve_plan_execution_step(
            planArn=arn, executionId=execution_id, stepName="Approve", approval="approve"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-approving an already-completed step, got {code!r}"
    )
    expected = f"There is no active execution ongoing for plan {arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = arc_b.get_plan_execution(planArn=arn, executionId=execution_id)
    assert unchanged["executionState"] == "completed", (
        f"reapproval attempt must not alter executionState; expected 'completed', got "
        f"{unchanged['executionState']!r}"
    )
    assert unchanged["stepStates"][0]["status"] == "completed", (
        f"reapproval attempt must not alter stepStates[0].status; expected 'completed', got "
        f"{unchanged['stepStates'][0]['status']!r}"
    )


def _regional_client(ctx, region):
    return ctx.client("arc-region-switch", region=region)


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
    for attempt in range(20):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            if attempt == 19:
                raise
            time.sleep(1)
    # No further unconditional wait here: cross-service trust-policy propagation (this role
    # becoming assumable BY arc-region-switch, which lags IAM's own get_role visibility) is
    # bounded instead by _start_execution_with_retry's AccessDeniedException retry below, which
    # already exists to absorb exactly this lag with a stated reason and a deadline.
    return arn


def _create_approval_role(ctx, account_id):
    # Trusts the WHOLE account (not the arc-region-switch service), because this role is the one
    # OUR caller assumes to satisfy ApprovePlanExecutionStep's approver-identity check -- a
    # distinct trust relationship from the plan's service-assumed executionRole.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-arcapprover-")
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
    for attempt in range(20):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            if attempt == 19:
                raise
            time.sleep(1)
    return arn


def _call_with_retry(fn, retryable_codes, attempts=6, sleep_s=3):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in retryable_codes:
                last_exc = e
                time.sleep(sleep_s)
                continue
            raise
    raise last_exc


def _assume_role_client(ctx, region, role_arn):
    from botocore.exceptions import ClientError

    sts = ctx.client("sts")
    deadline = time.monotonic() + 40.0
    last_exc = None
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-approver-")
            )["Credentials"]
            break
        except ClientError as e:
            # AccessDenied here is the same freshly-created-role propagation lag as elsewhere in
            # this file, not a real authorization gap: the trust policy was just attached above.
            if e.response["Error"]["Code"] == "AccessDenied":
                last_exc = e
                time.sleep(5)
                continue
            raise
    if creds is None:
        raise AssertionError(
            f"could not assume the freshly created approval role within 40s; last error: {last_exc!r}"
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


def _start_execution_with_retry(arc, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(8):
        try:
            return arc.start_plan_execution(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            # ResourceNotFoundException here is transient control-plane propagation lag: a plan
            # ARN handed back by CreatePlan can briefly not yet be visible to StartPlanExecution
            # (observed against real AWS), not the plan genuinely not existing.
            if code in ("AccessDeniedException", "IllegalArgumentException", "ResourceNotFoundException"):
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
