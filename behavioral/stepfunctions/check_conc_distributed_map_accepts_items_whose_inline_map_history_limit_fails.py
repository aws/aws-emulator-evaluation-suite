"""conc-distributed-map-accepts-items-whose-inline-map-history-limit-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-distributed-map-accepts-items-whose-inline-map-history-limit-fails"
GROUP = 'distributed_map'
SERVICES = ['stepfunctions']

_N_ITEMS = 3200  # 3 Pass states per item: ~8 history events each, so > 25,000 inline
_HISTORY_CAUSE = "The execution reached the maximum number of history events (25000)."


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """The 3200 items that make an INLINE Map fail States.Runtime at the 25,000-event history limit
    are processed in full by the equivalent DISTRIBUTED Map; only ProcessorConfig.Mode differs.
    """
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_role(ctx, account_id)
    inline_sm = _create_state_machine(ctx, _definition("INLINE"), role_arn)
    dist_sm = _create_state_machine(ctx, _definition("DISTRIBUTED"), role_arn)
    items = list(range(_N_ITEMS))

    inline, dist = _run_pair(ctx, inline_sm, dist_sm, {"items": items}, timeout_s=250.0)

    # --- positive: the Distributed Map processes every item ---
    assert dist["status"] == "SUCCEEDED", (
        f'the DISTRIBUTED Map over {_N_ITEMS!r} items was {dist["status"]!r}: '
        f'{dist.get("error")!r} {dist.get("cause")!r}'
    )
    assert json.loads(dist["output"]) == items, (
        f"the DISTRIBUTED Map's collected output does not echo the {_N_ITEMS!r} items in order"
    )
    counts = sfn.describe_map_run(mapRunArn=_one_map_run(ctx, dist["executionArn"]))["itemCounts"]
    assert (counts["total"], counts["succeeded"], counts["failed"]) == (_N_ITEMS, _N_ITEMS, 0), (
        f"DescribeMapRun itemCounts {counts!r}"
    )

    # --- negative: the INLINE Map over the same items hits the history limit ---
    # Inline Map has no 40-item limit (40 is its concurrency ceiling); history is what it hits.
    assert inline["status"] == "FAILED", (
        f'the INLINE Map over {_N_ITEMS!r} items was {inline["status"]!r}, expected FAILED'
    )
    assert (inline.get("error"), inline.get("cause")) == ("States.Runtime", _HISTORY_CAUSE), (
        f'the INLINE Map failed with {inline.get("error")!r} / {inline.get("cause")!r}'
    )
    assert inline.get("output") is None, (
        f'a history-limited execution produced output: {inline.get("output")!r:.200}'
    )
    last = sfn.get_execution_history(
        executionArn=inline["executionArn"], reverseOrder=True, maxResults=1)["events"][0]
    assert (last["id"], last["type"]) == (25000, "ExecutionFailed"), (
        f'the INLINE execution\'s final event is #{last["id"]!r} {last["type"]!r}, expected '
        f"#25000 ExecutionFailed"
    )


def _definition(mode):
    config = {"Mode": mode}
    if mode == "DISTRIBUTED":
        config["ExecutionType"] = "EXPRESS"
    return {
        "StartAt": "Fan",
        "States": {"Fan": {
            "Type": "Map",
            "ItemsPath": "$.items",
            "ItemProcessor": {
                "ProcessorConfig": config,
                "StartAt": "A",
                "States": {
                    "A": {"Type": "Pass", "Next": "B"},
                    "B": {"Type": "Pass", "Next": "C"},
                    "C": {"Type": "Pass", "End": True},
                },
            },
            "End": True,
        }},
    }


# ===== helpers =====
def _create_role(ctx, account_id):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-dmaprole-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn distributed-map execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {"Effect": "Allow", "Action": ["states:StartExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account_id}:execution:*:*"},
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-dmap-")
    deadline = _deadline(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume", "cannot be assumed", "sts:AssumeRole",
    "States.Permissions", "AccessDenied",
)


def _start(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _run_pair(ctx, inline_sm, dist_sm, payload, *, timeout_s, propagation_s=120.0):
    """Start both executions together and poll both to terminal.

    Only the DISTRIBUTED run needs the role's states:StartExecution, so only its failure on
    the IAM-propagation race earns it a fresh attempt; the inline run is started once.
    """
    inline_arn = _start(ctx, inline_sm, payload)
    dist = None
    deadline = _deadline(ctx, propagation_s)
    while True:
        dist_arn = _start(ctx, dist_sm, payload)
        dist = _wait_terminal(ctx, dist_arn, timeout_s=timeout_s)
        blob = (dist.get("cause") or "") + (dist.get("error") or "")
        if dist["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    return _wait_terminal(ctx, inline_arn, timeout_s=timeout_s), dist


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _one_map_run(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    runs, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_map_runs(**kwargs)
        runs.extend(resp["mapRuns"])
        token = resp.get("nextToken")
        if not token:
            break
    assert len(runs) == 1, f"expected exactly one map run for {exec_arn!r}, got {runs!r}"
    return runs[0]["mapRunArn"]


def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
