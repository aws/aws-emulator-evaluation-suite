"""start-plan-execution-post-recovery-missing-id-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-plan-execution-post-recovery-missing-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["arc-region-switch"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartPlanExecution with action=postRecovery requires recoveryExecutionId; omitting it is
    rejected with IllegalArgumentException and creates no execution, while a normal
    action=activate request against the same plan succeeds (in-file positive control)."""
    arc = ctx.client("arc-region-switch")
    region_a, region_b = _pick_regions(ctx)
    role_arn = _create_execution_role(ctx)

    arn = arc.create_plan(
        name=_plan_name(ctx),
        regions=[region_a, region_b],
        recoveryApproach="activePassive",
        primaryRegion=region_a,
        executionRole=role_arn,
        workflows=[
            {"workflowTargetAction": "activate"},
            {"workflowTargetAction": "postRecovery"},
        ],
        tags={"sim2real": CHECK},
    )["plan"]["arn"]
    ctx.on_cleanup(lambda: _delete_plan_when_idle(arc, arn))

    # positive control FIRST: confirm a normal activate request is accepted in this account/role
    # before asserting anything about the postRecovery boundary -- if StartPlanExecution is
    # persistently denied even here, that's an environment limitation, not this boundary.
    started = _start_execution_with_retry(
        arc, planArn=arn, targetRegion=region_b, action="activate"
    )
    assert "executionId" in started, f"expected executionId in StartPlanExecution response, got {started}"
    executions = arc.list_plan_executions(planArn=arn)["items"]
    assert any(item["executionId"] == started["executionId"] for item in executions), (
        f"expected {started['executionId']} in ListPlanExecutions items, got {executions}"
    )

    code, message = _error(
        lambda: arc.start_plan_execution(planArn=arn, targetRegion=region_b, action="postRecovery")
    )
    assert code == "IllegalArgumentException", (
        f"expected IllegalArgumentException for postRecovery with no recoveryExecutionId, got {code!r}"
    )
    expected = (
        f"The recoveryExecutionId is missing or incorrectly formatted for the {arn}. Please "
        "provide the recoveryExecutionId in the format 'region/executionId' for Post Recovery "
        "execution."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # the rejected postRecovery attempt created no additional execution
    remaining = arc.list_plan_executions(planArn=arn)["items"]
    assert len(remaining) == 1, f"expected exactly 1 execution after the rejected postRecovery attempt, got {remaining}"


def _start_execution_with_retry(arc, **kwargs):
    """Retries AccessDeniedException/IllegalArgumentException (trust-policy propagation for the
    freshly created execution role) and ResourceNotFoundException (the just-created plan is not
    yet visible to StartPlanExecution -- observed on real AWS immediately after CreatePlan)."""
    from botocore.exceptions import ClientError

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
    if isinstance(last_exc, ClientError) and last_exc.response["Error"]["Code"] == "AccessDeniedException":

        raise AssertionError(
            "StartPlanExecution was persistently denied (AccessDeniedException with no detail) "
            "even for a freshly created, correctly-trust-policied execution role after 40s of "
            "retries; this sandbox account appears to withhold arc-region-switch execution "
            "privileges independent of the plan/role setup under test"
        )
    raise last_exc


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


def _pick_regions(ctx):
    # region_b is ctx.region, the region StartPlanExecution is called against; region_a is the
    # plan's other participating (primary) region, used only as metadata -- never dialed directly.
    region_b = ctx.region
    region_a = "us-west-2" if region_b != "us-west-2" else "us-east-1"
    return region_a, region_b


def _plan_name(ctx, prefix="sim2real-arc-"):
    return ctx.unique_name(prefix)[:32].rstrip("-")


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
    # trust-policy propagation to arc-region-switch's assumability check is covered by
    # _start_execution_with_retry's bounded retry on AccessDeniedException below -- no
    # separate unconditional wait needed here.
    return arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
