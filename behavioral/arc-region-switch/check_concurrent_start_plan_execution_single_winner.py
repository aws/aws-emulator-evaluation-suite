"""concurrent-start-plan-execution-single-winner."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-start-plan-execution-single-winner"
GROUP = "concurrency"
SERVICES = ["arc-region-switch"]

_TERMINAL_STATES = ("completed", "completedWithExceptions", "failed", "canceled")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent StartPlanExecution calls on one plan yield exactly one winner, every other racer
    gets IllegalStateException, and ListPlanExecutions shows the winner as the only active
    execution beside the terminal warm-up run."""
    arc = ctx.client("arc-region-switch")
    role_arn = _create_execution_role(ctx)
    approver = ctx.client("arc-region-switch", creds=_assume_role_with_retry(ctx, role_arn))
    region_a, region_b = _pick_regions(ctx)
    arn = _create_plan_with_approval_workflow(ctx, role_arn, region_a, region_b)
    ctx.on_cleanup(lambda: _safe_delete(arc, arn))

    # warm-up: confirm StartPlanExecution is viable at all in this account/role before racing --
    # if it's persistently denied for reasons outside this check's control, fail loudly rather
    # than misreport "no winner" as a race-semantics finding.
    warmup = _start_execution_with_retry(ctx, arc, planArn=arn, targetRegion=region_b, action="activate")
    _wait_for_step_pending_approval(arc, arn, warmup["executionId"], "Approve")
    approver.approve_plan_execution_step(
        planArn=arn, executionId=warmup["executionId"], stepName="Approve", approval="decline"
    )
    _poll_until(
        lambda: arc.get_plan_execution(planArn=arn, executionId=warmup["executionId"]),
        lambda r: r["executionState"] in _TERMINAL_STATES,
        timeout_s=90,
    )

    n_racers = 5

    def _racer(_i):
        try:
            resp = arc.start_plan_execution(planArn=arn, targetRegion=region_b, action="activate")
            return ("ok", resp["executionId"])
        except Exception as e:
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_racer, range(n_racers)))

    wins = [r for r in results if r[0] == "ok"]
    losses = [r for r in results if r[0] == "error"]

    assert len(wins) == 1, f"expected exactly 1 winner among {n_racers} concurrent racers, got {wins}"
    assert len(losses) == n_racers - 1, f"expected {n_racers - 1} losers, got {losses}"
    assert all(code == "IllegalStateException" for _, code, _m in losses), (
        f"expected every racer that lost the race to be rejected with IllegalStateException, got {losses}"
    )
    expected = f"There is already an execution ongoing for plan {arn}"
    assert all(message == expected for _, _c, message in losses), (
        f"expected every losing racer's message to be {expected!r}, got {losses}"
    )

    # ListPlanExecutions returns the plan's whole execution HISTORY, not just active ones --
    # terminal executions such as the warm-up execution are listed alongside the winner.
    # The real invariant is that at most one is ever ACTIVE at a time.
    executions = arc.list_plan_executions(planArn=arn)["items"]
    active = [e for e in executions if e["executionState"] not in _TERMINAL_STATES]
    assert len(executions) == 2, f"expected the warm-up plus the winner in the history, got {executions}"
    assert len(active) == 1, f"expected exactly 1 active execution after the race, got {executions}"
    assert active[0]["executionId"] == wins[0][1], (
        f"expected the active execution to be the race winner {wins[0][1]!r}, got {active[0]['executionId']!r}"
    )

    # cleanup: approve to bring the winning execution to a terminal state
    _wait_for_step_pending_approval(arc, arn, wins[0][1], "Approve")
    approver.approve_plan_execution_step(
        planArn=arn, executionId=wins[0][1], stepName="Approve", approval="approve"
    )
    _poll_until(
        lambda: arc.get_plan_execution(planArn=arn, executionId=wins[0][1]),
        lambda r: r["executionState"] in _TERMINAL_STATES,
        timeout_s=90,
    )


# ===== helpers =====
def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the run's remaining time."""
    deadline = time.monotonic() + timeout_s
    left = ctx.time_left()
    return deadline if left is None else min(deadline, time.monotonic() + left)


def _start_execution_with_retry(ctx, arc, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline = _deadline(ctx, 40.0)
    while True:
        try:
            return arc.start_plan_execution(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            # ResourceNotFoundException: a plan that GetPlan already reflects can still 404 out of
            # StartPlanExecution for a few seconds -- the execution engine lags the plan metadata store when compiling a freshly created plan
            # into something it can run. Bounded retry on that lag; anything else is a real defect.
            if code in ("AccessDeniedException", "IllegalArgumentException", "ResourceNotFoundException"):
                last_exc = e
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
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
    if isinstance(last_exc, ClientError) and last_exc.response["Error"]["Code"] == "ResourceNotFoundException":
        raise AssertionError(
            f"StartPlanExecution still returned ResourceNotFoundException for {kwargs.get('planArn')} "
            "after 40s of retries, even though the plan exists -- the execution-engine sync lag "
            "measured elsewhere did not clear in time"
        )
    raise last_exc


def _assume_role_with_retry(ctx, role_arn):
    # The trust policy update granting the caller sts:AssumeRole can lag IAM's own propagation
    # window the same way the arc-region-switch PassRole grant does -- retry AccessDenied only.
    from botocore.exceptions import ClientError

    sts = ctx.client("sts")
    last_exc = None
    deadline = _deadline(ctx, 40.0)
    while True:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-approver-")[:64]
            )["Credentials"]
            return {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                last_exc = e
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
                continue
            raise
    raise AssertionError(
        f"AssumeRole on the freshly created execution role {role_arn} was still denied after "
        f"40s of retries: {last_exc}"
    )


def _wait_for_step_pending_approval(arc, arn, execution_id, step_name, timeout_s=60.0, interval_s=2.0):
    # StartPlanExecution can return before the named step's status is queryable as
    # "pendingApproval" -- ApprovePlanExecutionStep can answer
    # ResourceNotFoundException("Manual approval not pending...") a moment after a
    # successful start. Poll the step's own reported status rather than guessing a sleep length.
    def _step_status():
        # stepStates is observed EMPTY for a moment right after StartPlanExecution succeeds --
        # the same engine lag, one level deeper. Absence is a poll-again signal here, not a
        # defect: the step name is fixed by the workflow this check itself created.
        execution = arc.get_plan_execution(planArn=arn, executionId=execution_id)
        for step in execution["stepStates"]:
            if step["name"] == step_name:
                return step["status"]
        return None

    _poll_until(_step_status, lambda status: status == "pendingApproval", timeout_s=timeout_s, interval_s=interval_s)


def _pick_regions(ctx):
    # region_b is ctx.region, the region StartPlanExecution is called against; region_a is the
    # plan's other participating (primary) region, used only as metadata -- never dialed directly.
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
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
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
                # The plan's approvalRole (below) must be assumed by whoever calls
                # ApprovePlanExecutionStep -- real AWS rejects that call from any OTHER
                # identity with AccessDeniedException, even one with an allow-all policy.
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
        tags={"sim2real-check": CHECK},
    )
    return resp["plan"]["arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
