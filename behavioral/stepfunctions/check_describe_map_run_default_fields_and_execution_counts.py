"""describe-map-run-default-fields-and-execution-counts."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-map-run-default-fields-and-execution-counts"
GROUP = "map_state"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A finished Distributed Map Run with no concurrency/tolerance knobs reports the defaults
    (maxConcurrency 2147483647, tolerances 0, redriveCount 0, no redriveDate), and its
    executionCounts agree with itemCounts since every item ran as its own child execution."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    definition = json.dumps({
        "StartAt": "Map",
        "States": {
            "Map": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Item",
                    "States": {"Item": {"Type": "Pass", "End": True}},
                },
                "End": True,
            }
        },
    })
    sm_arn = _create_state_machine_with_retry(ctx, sfn, ctx.unique_name("sim2real-behav-sm-"), definition, role_arn)

    items = [{"n": 1}, {"n": 2}, {"n": 3}]
    exec_arn = None
    final = None
    left = ctx.time_left()
    deadline = time.monotonic() + (50.0 if left is None else min(50.0, left))
    attempts = 0
    while True:
        attempts += 1
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-exec-"),
            input=json.dumps({"items": items}),
        )["executionArn"]
        ctx.on_cleanup(lambda arn=exec_arn: _best_effort_stop(sfn, arn))

        map_run_arn = _poll_for_map_run(ctx, exec_arn, timeout_s=60.0)
        final = _poll_until(
            lambda: sfn.describe_map_run(mapRunArn=map_run_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "ABORTED"),
            timeout_s=120.0,
            interval_s=2.0,
        )
        if final["status"] == "SUCCEEDED":
            break
        # The role's trust policy can still be propagating when the Map Run's child executions
        # assume it, failing with "failed to assume the provided role"; retry a fresh execution.
        desc = sfn.describe_execution(executionArn=exec_arn)
        if "assume the provided role" not in (desc.get("cause") or ""):
            raise AssertionError(
                f"expected the Map Run to SUCCEED, got status={final['status']!r} "
                f"itemCounts={final.get('itemCounts')!r} execution error={desc.get('error')!r} "
                f"cause={desc.get('cause')!r}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the Map Run never SUCCEEDED across {attempts} attempts; role trust propagation "
                f"never settled. last status={final['status']!r}"
            )
        time.sleep(2)

    assert final["executionArn"] == exec_arn, (
        f"DescribeMapRun's executionArn was {final['executionArn']!r}, expected {exec_arn!r}"
    )
    # The Smithy model declares `maxConcurrency`'s default as 0, but a Map state whose
    # definition never set MaxConcurrency reports 2147483647 (int32 max) here, not 0 -- real
    # AWS's actual "unbounded" sentinel.
    assert final["maxConcurrency"] == 2147483647, (
        f"an unset MaxConcurrency must report AWS's unbounded sentinel 2147483647 on "
        f"DescribeMapRun, got {final['maxConcurrency']!r}"
    )
    assert final["toleratedFailurePercentage"] == 0.0, (
        f"an unset ToleratedFailurePercentage must default to 0.0, got "
        f"{final['toleratedFailurePercentage']!r}"
    )
    assert final["toleratedFailureCount"] == 0, (
        f"an unset ToleratedFailureCount must default to 0, got {final['toleratedFailureCount']!r}"
    )
    assert final.get("redriveCount", -1) == 0, (
        f"a never-redriven Map Run must report redriveCount 0, got {final.get('redriveCount')!r}"
    )
    assert "redriveDate" not in final, (
        f"a never-redriven Map Run must report no redriveDate at all, got "
        f"{final.get('redriveDate')!r}"
    )

    item_counts = final["itemCounts"]
    assert item_counts["total"] == len(items), f"itemCounts.total was {item_counts!r}, expected {len(items)}"
    assert item_counts["succeeded"] == len(items), f"itemCounts.succeeded was {item_counts!r}, expected {len(items)}"
    assert item_counts["failed"] == 0, f"itemCounts.failed was {item_counts!r}, expected 0"

    exec_counts = final["executionCounts"]
    assert exec_counts["total"] == len(items), (
        f"executionCounts.total was {exec_counts!r}; one child WORKFLOW EXECUTION per item is "
        f"expected since ItemProcessor is STANDARD/DISTRIBUTED, giving {len(items)}"
    )
    assert exec_counts["succeeded"] == len(items), f"executionCounts.succeeded was {exec_counts!r}, expected {len(items)}"
    assert exec_counts["failed"] == 0, f"executionCounts.failed was {exec_counts!r}, expected 0"


def _best_effort_stop(sfn, exec_arn):
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
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


def _poll_for_map_run(ctx, exec_arn, timeout_s=60.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        runs = sfn.list_map_runs(executionArn=exec_arn).get("mapRuns", [])
        if runs:
            return runs[0]["mapRunArn"]
        time.sleep(interval_s)
    raise AssertionError(f"no Map Run was ever scheduled for execution {exec_arn} within {timeout_s}s")


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sfn-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine_with_retry(ctx, sfn, name, definition, role_arn, timeout_s=90.0):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created role's
    trust/PassRole propagates, instead of a fixed sleep before the first attempt."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
