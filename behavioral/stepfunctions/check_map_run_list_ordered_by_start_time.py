"""map-run-list-ordered-by-start-time."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-run-list-ordered-by-start-time"
GROUP = "ordering"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single execution with two sequential Distributed Map states produces two Map Runs that
    ListMapRuns lists stably across calls, and Map1's run starts no later than Map2's."""
    sfn = ctx.client("stepfunctions")

    partition, account_id = _partition_and_account(ctx)
    name = ctx.unique_name("sim2real-behav-maprunord-")
    sm_arn = f"arn:{partition}:states:{ctx.region}:{account_id}:stateMachine:{name}"
    exec_arn_pattern = f"arn:{partition}:states:{ctx.region}:{account_id}:execution:{name}:*"

    role_arn = _create_sfn_role(
        ctx,
        extra_statements=[
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn},
            {
                "Effect": "Allow",
                "Action": ["states:DescribeExecution", "states:StopExecution"],
                "Resource": exec_arn_pattern,
            },
        ],
    )

    # NOTE: state names must be unique across the *entire* state machine,
    # including nested ItemProcessor scopes for distributed Map states -
    # reusing "Pass" in both processors triggers a DUPLICATE_STATE_NAME
    # validation error on real AWS, so each processor gets its own name.
    processor1 = {
        "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
        "StartAt": "Pass1",
        "States": {"Pass1": {"Type": "Pass", "End": True}},
    }
    processor2 = {
        "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
        "StartAt": "Pass2",
        "States": {"Pass2": {"Type": "Pass", "End": True}},
    }
    definition = json.dumps(
        {
            "StartAt": "Map1",
            "States": {
                "Map1": {
                    "Type": "Map",
                    "Label": "Map1",
                    "ItemProcessor": processor1,
                    "ItemsPath": "$.items",
                    "ResultPath": "$.map1Result",
                    "MaxConcurrency": 1,
                    "Next": "Map2",
                },
                "Map2": {
                    "Type": "Map",
                    "Label": "Map2",
                    "ItemProcessor": processor2,
                    "ItemsPath": "$.items",
                    "MaxConcurrency": 1,
                    "End": True,
                },
            },
        }
    )

    created_sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    assert created_sm_arn == sm_arn, "computed ARN did not match the created state machine ARN"
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # Freshly-created IAM roles can take a little while to fully propagate for
    # *runtime* AssumeRole (as opposed to the control-plane retry already in
    # _create_state_machine). A Distributed Map's child executions assume that
    # role to run, so the first attempt can fail almost immediately while
    # propagation finishes. Retry with a fresh execution until a deadline.
    final_exec = None
    left = ctx.time_left()
    deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    attempts = 0
    while True:
        attempts += 1
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("exec-"),
            input=json.dumps({"items": [1, 2]}),
        )["executionArn"]

        final_exec = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] != "RUNNING",
            timeout_s=60.0,
            interval_s=3.0,
        )
        if final_exec["status"] == "SUCCEEDED":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"execution did not succeed after {attempts} attempts; last={final_exec}"
            )
        time.sleep(2)

    def _list_all_map_runs():
        items = []
        token = None
        while True:
            kwargs = {"executionArn": exec_arn}
            if token:
                kwargs["nextToken"] = token
            resp = sfn.list_map_runs(**kwargs)
            items.extend(resp["mapRuns"])
            token = resp.get("nextToken")
            if not token:
                break
        return items

    runs1 = _list_all_map_runs()
    assert len(runs1) == 2, f"expected exactly 2 map runs, got {len(runs1)}"

    runs2 = _list_all_map_runs()
    assert [r["mapRunArn"] for r in runs2] == [r["mapRunArn"] for r in runs1], (
        "ListMapRuns order changed between two identical calls"
    )

    # ListMapRuns documents no result order, so each run is identified by the Map state label
    # in its ARN (mapRun:<stateMachine>/<label>:<id>) and the runs compare by startDate.
    start_by_label = {
        r["mapRunArn"].split(":")[-2].split("/")[-1]:
            sfn.describe_map_run(mapRunArn=r["mapRunArn"])["startDate"]
        for r in runs1
    }
    assert sorted(start_by_label) == ["Map1", "Map2"], (
        f"expected one Map Run per Map state label, got {[r['mapRunArn'] for r in runs1]}"
    )
    assert start_by_label["Map1"] <= start_by_label["Map2"], (
        f"Map1 runs before Map2, but their Map Runs started at {start_by_label}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _partition_and_account(ctx):
    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    arn_parts = ident["Arn"].split(":")
    return arn_parts[1], ident["Account"]


def _create_sfn_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = list(extra_statements or [])
    if not statements:
        statements = [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # IAM role/policy propagation lag is handled by the bounded retry in
    # _create_state_machine (it retries AccessDeniedException on its own
    # deadline), not by waiting here.
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, sfn, name, definition, role_arn, type_="STANDARD"):
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type=type_
            )
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
