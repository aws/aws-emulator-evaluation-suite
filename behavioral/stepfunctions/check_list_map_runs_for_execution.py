"""list-map-runs-for-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-map-runs-for-execution"
GROUP = 'map_state'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # A DISTRIBUTED Map runs its items as child executions under this role.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-map", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-map"))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _asl_map_wait(item_wait_seconds=3, max_concurrency=1):
    return {
        "Comment": "behavioral-map-wait",
        "StartAt": "Map",
        "States": {
            "Map": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": max_concurrency,
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "ItemWait",
                    "States": {"ItemWait": {"Type": "Wait", "Seconds": item_wait_seconds, "End": True}},
                },
                "End": True,
            }
        },
    }


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real-behav-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _wait_map_run_status(ctx, map_run_arn, statuses, *, timeout_s=90, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_map_run(mapRunArn=map_run_arn)
        if last["status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"map run {map_run_arn} status not in {statuses} within {timeout_s}s: {last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMapRuns for an execution with one Map state lists exactly one Map Run, paired with that
    execution's ARN and a stateMachineArn under the parent state machine, and DescribeMapRun on it
    returns the same mapRunArn."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_map_wait(item_wait_seconds=3, max_concurrency=2))
    exec_arn = _start_execution(ctx, arn, input_data={"items": [1, 2, 3]})

    deadline = time.monotonic() + 30
    map_runs = []
    while time.monotonic() < deadline:
        map_runs = sfn.list_map_runs(executionArn=exec_arn)["mapRuns"]
        if len(map_runs) >= 1:
            break
        time.sleep(1.0)
    assert len(map_runs) == 1, f"expected exactly one Map Run for this single-Map execution, got {map_runs}"
    entry = map_runs[0]
    assert entry["executionArn"] == exec_arn, f"expected the listed Map Run's executionArn to match, got {entry}"
    assert entry["stateMachineArn"].startswith(arn), (
        f"expected the listed Map Run's stateMachineArn to reference the parent state machine {arn}, got {entry}"
    )

    described = sfn.describe_map_run(mapRunArn=entry["mapRunArn"])
    assert described["mapRunArn"] == entry["mapRunArn"], (
        f"expected an independent DescribeMapRun to reflect the same mapRunArn {entry['mapRunArn']!r} "
        f"returned by ListMapRuns, got {described}"
    )

    _wait_map_run_status(ctx, entry["mapRunArn"], {"SUCCEEDED", "FAILED", "ABORTED"}, timeout_s=90)
    _wait_execution_complete(ctx, exec_arn, timeout_s=30)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
