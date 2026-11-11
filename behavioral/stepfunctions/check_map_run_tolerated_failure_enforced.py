"""map-run-tolerated-failure-enforced."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "map-run-tolerated-failure-enforced"
GROUP = "server-side"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateMapRun's toleratedFailureCount is enforced server-side: a Distributed Map Run stays
    RUNNING while failures are within tolerance, then flips to FAILED once the threshold is breached.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_distributed_map_role(ctx)

    definition = json.dumps(
        {
            "StartAt": "MapState",
            "States": {
                "MapState": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "MaxConcurrency": 1,
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                        "StartAt": "WaitItem",
                        "States": {
                            "WaitItem": {
                                "Type": "Wait",
                                "SecondsPath": "$.delaySeconds",
                                "Next": "CheckItem",
                            },
                            "CheckItem": {
                                "Type": "Choice",
                                "Choices": [
                                    {
                                        "Variable": "$.outcome",
                                        "StringEquals": "fail",
                                        "Next": "FailItem",
                                    }
                                ],
                                "Default": "SucceedItem",
                            },
                            "FailItem": {
                                "Type": "Fail",
                                "Error": "ProbeError",
                                "Cause": "intentional failure for tolerance test",
                            },
                            "SucceedItem": {"Type": "Succeed"},
                        },
                    },
                    "End": True,
                }
            },
        }
    )
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # Distributed Map ItemProcessors cannot dispatch Activity tasks, so failures are driven by
    # Wait/Fail states. Item 1's 20s Wait outlasts observing RUNNING plus the UpdateMapRun call
    # (default toleratedFailureCount=0 would otherwise fail the run first); MaxConcurrency=1
    # runs items sequentially, so item 2's shorter delay cannot race.
    items = [
        {"outcome": "fail", "delaySeconds": 20},
        {"outcome": "fail", "delaySeconds": 9},
    ]
    # Child executions assume the fresh role at runtime; before its policy propagates the first
    # child fails instantly and (tolerance 0) the map run goes terminal before RUNNING is seen.
    # A terminal status inside item 1's Wait window is that signature: retry with a new execution.
    map_run_arn = None
    exec_arn = None
    bootstrapped = None
    last_error = None
    left = ctx.time_left()
    retry_deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    attempt = 0
    while True:
        if attempt and time.monotonic() >= retry_deadline:
            raise AssertionError(f"map run never bootstrapped to RUNNING after retries: {last_error}")
        attempt += 1
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"items": items})
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))

        runs = _first_match(
            lambda: sfn.list_map_runs(executionArn=exec_arn)["mapRuns"],
            lambda runs: len(runs) > 0,
            timeout_s=30,
        )
        if runs is None:
            last_error = f"no map run listed within 30s (attempt {attempt})"
            time.sleep(2)
            continue
        map_run_arn = runs[0]["mapRunArn"]

        bootstrapped = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            bootstrapped = sfn.describe_map_run(mapRunArn=map_run_arn)
            if bootstrapped["status"] == "RUNNING":
                break
            if bootstrapped["status"] in ("FAILED", "SUCCEEDED", "ABORTED"):
                # Terminal before item 1's 20s Wait could elapse: propagation failure; retry.
                break
            time.sleep(1)

        if bootstrapped is not None and bootstrapped["status"] == "RUNNING":
            break
        last_error = AssertionError(
            f"map run did not reach RUNNING within bootstrap window "
            f"(attempt {attempt}): {bootstrapped}"
        )
        time.sleep(2)

    assert bootstrapped["status"] == "RUNNING", bootstrapped

    # Raise tolerance before any failure happens, avoiding a race with the default of 0.
    sfn.update_map_run(mapRunArn=map_run_arn, toleratedFailureCount=1, maxConcurrency=1)
    updated = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert updated["toleratedFailureCount"] == 1, updated

    # First failure is within tolerance, so the Map Run must keep running; item 2's Wait gives
    # a window to observe that before the second failure.
    after_first = _poll_until(
        lambda: sfn.describe_map_run(mapRunArn=map_run_arn),
        lambda d: d["itemCounts"]["failed"] >= 1,
        timeout_s=40,
    )
    assert after_first["status"] == "RUNNING", (
        f"map run should tolerate 1 failure and stay RUNNING, got {after_first['status']}"
    )

    final_map_run = _poll_until(
        lambda: sfn.describe_map_run(mapRunArn=map_run_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=40,
    )
    assert final_map_run["status"] == "FAILED", (
        f"expected map run FAILED after breaching tolerance, got {final_map_run['status']}"
    )
    assert final_map_run["itemCounts"]["failed"] >= 2, final_map_run["itemCounts"]

    final_execution = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30,
    )
    assert final_execution["status"] == "FAILED", (
        f"map run failure must propagate to parent execution, got {final_execution['status']}"
    )


def _create_distributed_map_role(ctx) -> str:
    iam = ctx.client("iam")
    account_id = ctx.account
    region = ctx.region
    role_name = ctx.unique_name("sim2real-behav-sfn-maprole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution"],
                "Resource": f"arn:aws:states:{region}:{account_id}:stateMachine:*",
            },
            {
                "Effect": "Allow",
                "Action": ["states:DescribeExecution", "states:StopExecution"],
                "Resource": f"arn:aws:states:{region}:{account_id}:execution:*:*",
            },
        ],
    }
    policy_name = "sim2real-behav-distributed-map-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine(ctx, definition: str, role_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    last_error = None
    for _ in range(15):
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except Exception as exc:  # noqa: BLE001 - retry on IAM role propagation delay
            last_error = exc
            time.sleep(2)
    raise AssertionError(f"could not create state machine (role propagation?): {last_error}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 1.5) -> Any:
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {result}")


def _first_match(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 1.5) -> Any:
    """The first probe result meeting ``predicate`` within ``timeout_s``, else None."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return None


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="test cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
