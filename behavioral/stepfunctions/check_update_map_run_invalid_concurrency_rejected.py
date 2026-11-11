"""update-map-run-invalid-concurrency-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-map-run-invalid-concurrency-rejected"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMapRun rejects an out-of-range toleratedFailurePercentage (0-100) on a running map
    run with ValidationException and leaves the run unchanged, after a positive control proves
    an in-range update on the same map run takes effect."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DISTRIBUTED_MAP_DEFINITION)
    sfn = ctx.client("stepfunctions")

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-exec-"),
        input=json.dumps({"items": [1, 2]}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: sfn.stop_execution(executionArn=exec_arn)))

    map_run_arn = _poll_until(
        lambda: sfn.list_map_runs(executionArn=exec_arn)["mapRuns"],
        lambda runs: len(runs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )[0]["mapRunArn"]

    sfn.update_map_run(mapRunArn=map_run_arn, toleratedFailurePercentage=10.0)
    before = sfn.describe_map_run(mapRunArn=map_run_arn)["toleratedFailurePercentage"]
    assert before == 10.0, f"positive control: in-range UpdateMapRun did not take effect, got {before}"

    code, message = _error(
        lambda: sfn.update_map_run(mapRunArn=map_run_arn, toleratedFailurePercentage=150.0)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value '150.0' at 'toleratedFailurePercentage' failed to "
        "satisfy constraint: Member must have value less than or equal to 100"
    ), f"unexpected ValidationException message: {message!r}"

    after = sfn.describe_map_run(mapRunArn=map_run_arn)["toleratedFailurePercentage"]
    assert after == before, f"rejected update mutated toleratedFailurePercentage: {before} -> {after}"


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
                "States": {"Wait": {"Type": "Wait", "Seconds": 6, "End": True}},
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


# StopExecution is a no-op on a terminal execution; these codes mean already deleted.
_GONE_CODES = ("ExecutionDoesNotExist", "StateMachineDoesNotExist", "NoSuchEntity")


def _ignore_gone(fn):
    """Run a teardown call; only a resource that is already gone is not an error."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises, because a
    target accepting what real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
        _ignore_gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _ignore_gone(lambda: iam.delete_role(RoleName=role_name))

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
    ctx.on_cleanup(lambda: _ignore_gone(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
