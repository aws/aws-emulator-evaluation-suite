"""update-map-run-validation-exception."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-map-run-validation-exception"
GROUP = 'map_state'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll: the bounded retry in _create_state_machine
    # and the trust-race retry in _start_map_execution_get_running_map_run absorb it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _asl_map_wait(item_wait_seconds, max_concurrency):
    """A DISTRIBUTED Map over $.items whose ItemProcessor Waits N seconds per item.

    DISTRIBUTED mode is what spawns a Map Run visible via ListMapRuns/DescribeMapRun."""
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


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
    "AccessDeniedException",
)


def _start_map_execution_get_running_map_run(
    ctx, sm_arn, input_data, *, max_attempts=6, wait_between=15, settle_timeout_s=30
):
    """Start a Distributed Map execution; return (exec_arn, map_run_arn) once its Map Run runs.

    Child executions first use the role's StartExecution grant, so a propagation race is retried."""
    sfn = ctx.client("stepfunctions")
    last_cause = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
        deadline = time.monotonic() + settle_timeout_s
        result = None
        while time.monotonic() < deadline:
            runs = sfn.list_map_runs(executionArn=exec_arn).get("mapRuns", [])
            if runs:
                map_run = sfn.describe_map_run(mapRunArn=runs[0]["mapRunArn"])
                if map_run["status"] == "RUNNING":
                    return exec_arn, runs[0]["mapRunArn"]
                if map_run["status"] in ("FAILED", "ABORTED"):
                    result = ("map_run_failed", exec_arn, map_run)
                    break
                time.sleep(1.0)
                continue
            desc = sfn.describe_execution(executionArn=exec_arn)
            if desc["status"] == "FAILED":
                result = ("failed", exec_arn, desc)
                break
            time.sleep(1.0)
        if result is None:
            result = ("timeout", exec_arn, None)

        events = sfn.get_execution_history(executionArn=exec_arn)["events"]
        cause = ""
        for e in events:
            if e["type"] == "ExecutionFailed":
                cause = e.get("executionFailedEventDetails", {}).get("cause", "")
            if e["type"] == "MapRunFailed":
                cause = cause or e.get("mapRunFailedEventDetails", {}).get("cause", "")
        if any(m in cause for m in _TRUST_RACE_MARKERS):
            last_cause = cause
            time.sleep(wait_between)
            continue
        raise AssertionError(
            f"map execution failed for a reason unrelated to role propagation: {result}; cause={cause!r}"
        )
    raise AssertionError(
        f"could not obtain a RUNNING distributed Map Run after {max_attempts} attempts "
        f"(last cause: {last_cause!r})"
    )


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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMapRun on a running Map Run with only mapRunArn (no maxConcurrency or tolerated
    failure field) fails ValidationException rather than succeeding as a no-op."""
    sfn = ctx.client("stepfunctions")
    # Distributed Map child executions need the role to start, describe and stop executions.
    role_arn = _create_sfn_role(ctx, [
        {
            "Effect": "Allow",
            "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
            "Resource": "*",
        },
    ])
    # Serial 10s items keep the Map Run RUNNING while UpdateMapRun is called.
    definition = _asl_map_wait(item_wait_seconds=10, max_concurrency=1)
    arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn, map_run_arn = _start_map_execution_get_running_map_run(ctx, arn, {"items": [1, 2]})

    code, message = _error(lambda: sfn.update_map_run(mapRunArn=map_run_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "Either the max concurrency, the tolerated failure count, or the tolerated failure "
        "percentage must be specified"
    ), f"unexpected ValidationException message: {message!r}"

    _wait_map_run_status(ctx, map_run_arn, {"SUCCEEDED", "FAILED", "ABORTED"}, timeout_s=60)
    _wait_execution_complete(ctx, exec_arn, timeout_s=30)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
