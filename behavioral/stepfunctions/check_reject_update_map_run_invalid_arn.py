"""reject-update-map-run-invalid-arn."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "reject-update-map-run-invalid-arn"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMapRun against a syntactically invalid ARN fails with InvalidArn instead of
    succeeding, after a positive control proves UpdateMapRun takes effect on a running map run."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DISTRIBUTED_MAP_DEFINITION)

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-exec-"),
        input=json.dumps({"items": [1, 2, 3]}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: sfn.stop_execution(executionArn=exec_arn)))

    map_run_arn = _poll_until(
        lambda: sfn.list_map_runs(executionArn=exec_arn)["mapRuns"],
        lambda runs: len(runs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )[0]["mapRunArn"]

    # Positive control: a well-formed ARN against a real, running map run must
    # actually take effect.
    sfn.update_map_run(mapRunArn=map_run_arn, maxConcurrency=7)
    controlled = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert controlled["maxConcurrency"] == 7, (
        f"positive control failed: expected maxConcurrency 7, got {controlled['maxConcurrency']}"
    )

    bad_arn = "this-is-not-an-arn-" + ctx.unique_name("mr")
    code = message = None
    try:
        sfn.update_map_run(mapRunArn=bad_arn, maxConcurrency=5)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")

    assert code is not None, "UpdateMapRun on a malformed ARN unexpectedly succeeded"
    assert code == "InvalidArn", f"expected InvalidArn, got {code}"
    expected = f"Invalid Arn: 'Invalid ARN prefix: {bad_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the malformed call must not have touched the real map run.
    unaffected = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert unaffected["maxConcurrency"] == 7, (
        f"malformed-ARN call mutated the real map run: {unaffected['maxConcurrency']}"
    )


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
                "States": {"Wait": {"Type": "Wait", "Seconds": 20, "End": True}},
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)
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
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
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
