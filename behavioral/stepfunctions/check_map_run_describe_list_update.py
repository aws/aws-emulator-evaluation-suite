"""map-run-describe-list-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "map-run-describe-list-update"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Distributed Map execution creates a discoverable map run, visible via
    ListMapRuns/DescribeMapRun and mutable via UpdateMapRun while running."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DISTRIBUTED_MAP_DEFINITION)
    sfn = ctx.client("stepfunctions")

    # Freshly-created IAM roles can take a little while to fully propagate for
    # *runtime* AssumeRole (as opposed to the control-plane checks already
    # retried in _create_state_machine). A Distributed Map's child executions
    # assume that role to run, so the very first attempt can occasionally fail
    # almost immediately with an internal permissions error while propagation
    # finishes. Retry with a fresh execution until a deadline before giving up.
    described = None
    map_run_arn = None
    exec_arn = None
    last_status = None
    left = ctx.time_left()
    deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    while True:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-exec-"),
            input=json.dumps({"items": [1, 2, 3]}),
        )["executionArn"]

        map_run_arn = _poll_until(
            lambda: sfn.list_map_runs(executionArn=exec_arn)["mapRuns"],
            lambda runs: len(runs) >= 1,
            timeout_s=60.0,
            interval_s=2.0,
        )[0]["mapRunArn"]

        described = sfn.describe_map_run(mapRunArn=map_run_arn)
        last_status = described["status"]
        if last_status == "RUNNING":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"map run was never observed RUNNING across all attempts; last status={last_status}")
        if last_status != "SUCCEEDED":
            # A non-terminal, non-RUNNING status this early is the IAM-propagation
            # symptom described above; give it time before the next attempt. A
            # SUCCEEDED status just means this attempt's map run finished before we
            # could observe it running, which a fresh execution can outrun.
            time.sleep(2)

    assert described["executionArn"] == exec_arn, (described["executionArn"], exec_arn)
    assert described["maxConcurrency"] == 1, described["maxConcurrency"]

    # Mutate runtime settings while the map run is (most likely) still running.
    sfn.update_map_run(mapRunArn=map_run_arn, maxConcurrency=5, toleratedFailurePercentage=10)
    updated = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert updated["maxConcurrency"] == 5, updated["maxConcurrency"]
    assert updated["toleratedFailurePercentage"] == 10, updated["toleratedFailurePercentage"]

    final = _poll_until(
        lambda: sfn.describe_map_run(mapRunArn=map_run_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "ABORTED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["status"] == "SUCCEEDED", final["status"]

    exec_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert exec_final["status"] == "SUCCEEDED", exec_final["status"]



# ===== helpers =====
_DISTRIBUTED_MAP_DEFINITION = {
    "Comment": "distributed map test",
    "StartAt": "MapState",
    "States": {
        "MapState": {
            "Type": "Map",
            "ItemsPath": "$.items",
            "MaxConcurrency": 1,
            "ItemProcessor": {
                "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                "StartAt": "Wait",
                "States": {"Wait": {"Type": "Wait", "Seconds": 4, "End": True}},
            },
            "End": True,
        }
    },
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
