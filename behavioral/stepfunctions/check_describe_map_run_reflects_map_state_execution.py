"""describe-map-run-reflects-map-state-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-map-run-reflects-map-state-execution"
GROUP = 'map_state'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

# A Distributed Map runs its child workflow executions with the parent's execution role.
_SFN_MAP_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
        "Resource": "*",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, allowed to
    run the Distributed Map's child executions."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-map-children")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-map-children", PolicyDocument=_SFN_MAP_POLICY)
    return role_arn


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


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
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


def _get_map_run_arn_for_execution(ctx, exec_arn, *, timeout_s=30, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = sfn.list_map_runs(executionArn=exec_arn).get("mapRuns", [])
        if items:
            return items[0]["mapRunArn"]
        time.sleep(interval_s)
    raise AssertionError(f"no Map Run scheduled for execution {exec_arn} within {timeout_s}s")


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
    """A distributed Map state over 5 items produces a Map Run whose DescribeMapRun reports the
    execution's ARN, status SUCCEEDED, and itemCounts total and succeeded both equal to 5."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(
        ctx, _asl_map_wait(item_wait_seconds=2, max_concurrency=4), _create_sfn_role(ctx)
    )
    items = [1, 2, 3, 4, 5]
    # A freshly created role is not assumable by Step Functions until IAM propagates it, which a
    # Distributed Map reports as an assume-role failure; only that failure is retried, each time
    # with a fresh execution, within a bounded window.
    propagation_deadline = time.monotonic() + 120.0
    while True:
        exec_arn = _start_execution(ctx, arn, input_data={"items": items})

        map_run_arn = _get_map_run_arn_for_execution(ctx, exec_arn)
        described = sfn.describe_map_run(mapRunArn=map_run_arn)
        assert described["executionArn"] == exec_arn, f"expected the Map Run's executionArn to match, got {described}"

        final_map_run = _wait_map_run_status(ctx, map_run_arn, {"SUCCEEDED", "FAILED", "ABORTED"}, timeout_s=120)
        if final_map_run["status"] == "SUCCEEDED":
            break
        history = sfn.get_execution_history(executionArn=exec_arn)["events"]
        if ("failed to assume the provided role" in json.dumps(history, default=str)
                and time.monotonic() < propagation_deadline):
            time.sleep(5)
            continue
        raise AssertionError(f"expected the Map Run to SUCCEED, got {final_map_run}; history={history}")
    counts = final_map_run["itemCounts"]
    assert counts["total"] == len(items), f"expected itemCounts.total == {len(items)}, got {counts}"
    assert counts.get("succeeded", 0) == len(items), f"expected all items to succeed, got {counts}"

    _wait_execution_complete(ctx, exec_arn, timeout_s=30)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
