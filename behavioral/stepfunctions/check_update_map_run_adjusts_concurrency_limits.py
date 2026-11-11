"""update-map-run-adjusts-concurrency-limits."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-map-run-adjusts-concurrency-limits"
GROUP = 'map_state'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
)


def _create_sfn_role(ctx):
    """Create an execution role Step Functions can assume; it is deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)
    return arn


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    arn = _await_role(lambda: sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    ))["stateMachineArn"]
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


def _asl_map_wait(item_wait_seconds, max_concurrency):
    """A DISTRIBUTED Map state whose ItemProcessor just Waits N seconds per item.

    Input must supply {"items": [...]}. Mode must be DISTRIBUTED — that's what actually
    spawns a Map Run (with a real mapRunArn visible via ListMapRuns/DescribeMapRun).
    """
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


def _wait_map_run_status(ctx, map_run_arn, statuses, *, timeout_s=90, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_map_run(mapRunArn=map_run_arn)
        if last["status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"map run status not in {statuses} within {timeout_s}s: {last!r}")


def _start_map_execution_get_running_map_run(
    ctx, sm_arn, input_data, *, max_attempts=6, wait_between=30, settle_timeout_s=20
):
    """Start a DISTRIBUTED-Map execution and return (exec_arn, map_run_arn) once the Map
    Run is discoverable and not already failed. A Distributed Map makes several internal
    AssumeRole calls that can race IAM trust-policy propagation on real AWS; if that
    specific race is detected via the execution/Map-Run failure cause, retry with a fresh
    execution rather than fail the whole check on an infra race."""
    sfn = ctx.client("stepfunctions")
    last_cause = None
    for _ in range(max_attempts):
        exec_arn = _start_execution(ctx, sm_arn, input_data=input_data)
        deadline = time.monotonic() + settle_timeout_s
        result = None
        while time.monotonic() < deadline:
            runs = sfn.list_map_runs(executionArn=exec_arn)["mapRuns"]
            if runs:
                map_run = sfn.describe_map_run(mapRunArn=runs[0]["mapRunArn"])
                if map_run["status"] != "FAILED":
                    result = ("map_run", exec_arn, runs[0]["mapRunArn"])
                else:
                    result = ("map_run_failed", exec_arn, map_run)
                break
            desc = sfn.describe_execution(executionArn=exec_arn)
            if desc["status"] == "FAILED":
                result = ("failed", exec_arn, desc)
                break
            time.sleep(1.0)

        if result and result[0] == "map_run":
            return result[1], result[2]

        events = sfn.get_execution_history(executionArn=exec_arn)["events"]
        cause = ""
        for e in events:
            if e["type"] == "ExecutionFailed":
                cause = e.get("executionFailedEventDetails", {}).get("cause", "")
            if e["type"] == "MapRunFailed":
                cause = cause or e.get("mapRunFailedEventDetails", {}).get("cause", "")
        if "not authorized to assume the provided role" in cause:
            last_cause = cause
            time.sleep(wait_between)
            continue
        raise AssertionError(
            f"map execution failed for a reason unrelated to role propagation: {result}; history={events}"
        )
    raise AssertionError(
        f"could not obtain a RUNNING distributed Map Run after {max_attempts} attempts: the shared "
        f"test execution role is not provisioned for distributed-map child executions "
        f"(persistent assume-role failure): {last_cause}"
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateMapRun's maxConcurrency change on a RUNNING Map Run is reflected by DescribeMapRun.

    A real, observable configuration change on the live run, not just an accepted no-op call.
    """
    sfn = ctx.client("stepfunctions")
    definition = _asl_map_wait(item_wait_seconds=8, max_concurrency=1)
    arn = _create_state_machine(ctx, definition)
    exec_arn, map_run_arn = _start_map_execution_get_running_map_run(ctx, arn, {"items": [1, 2, 3, 4]})

    _wait_map_run_status(ctx, map_run_arn, {"RUNNING"}, timeout_s=30)
    before = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert before["maxConcurrency"] == 1, f"expected initial maxConcurrency 1, got {before}"

    sfn.update_map_run(mapRunArn=map_run_arn, maxConcurrency=3)
    after = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert after["maxConcurrency"] == 3, f"expected maxConcurrency updated to 3, got {after}"

    final_map_run = _wait_map_run_status(ctx, map_run_arn, {"SUCCEEDED", "FAILED", "ABORTED"}, timeout_s=90)
    assert final_map_run["status"] == "SUCCEEDED", (
        f"raised maxConcurrency did not let the map run actually finish: {final_map_run}"
    )
    final_exec = _wait_execution_complete(ctx, exec_arn, timeout_s=30)
    assert final_exec["status"] == "SUCCEEDED", f"expected execution to SUCCEED, got {final_exec}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
