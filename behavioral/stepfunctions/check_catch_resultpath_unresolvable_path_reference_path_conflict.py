"""catch-resultpath-unresolvable-path-reference-path-conflict."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catch-resultpath-unresolvable-path-reference-path-conflict"
GROUP = "error_handling"
SERVICES = ["stepfunctions"]

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

_REFERENCE_PATH_CONFLICT = "States.ReferencePathConflict"


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
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
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
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


def _run_to_completion(ctx, definition, input_data=None, *, timeout_s=30):
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    return _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Catch's ResultPath that cannot be applied to the input (an object path on an array)
    fails the whole execution with States.ReferencePathConflict naming the unresolved step.
    """
    definition = {
        "StartAt": "Wrapper",
        "States": {
            "Wrapper": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "F",
                        "States": {
                            "F": {
                                "Type": "Fail",
                                "Error": "BoomError",
                                "Cause": "boom cause",
                            }
                        },
                    }
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["BoomError"],
                        "ResultPath": "$.notExist.notExist",
                        "Next": "NotReached",
                    }
                ],
                "End": True,
            },
            "NotReached": {"Type": "Pass", "Result": "not-reached", "End": True},
        },
    }
    # The execution input is a JSON array, not an object: "$.notExist.notExist" cannot be
    # applied to it, which is the conflict this check is about.
    result = _run_to_completion(ctx, definition, [1, 2])
    assert result["status"] == "FAILED", (
        f"an unresolvable Catch ResultPath must fail the whole execution, got "
        f"status={result['status']!r}: {result!r}"
    )
    assert result.get("error") == _REFERENCE_PATH_CONFLICT, (
        f"expected error={_REFERENCE_PATH_CONFLICT!r} for an unresolvable ResultPath, got "
        f"{result.get('error')!r}: {result!r}"
    )
    assert result.get("cause") == 'Unable to apply step "notExist" to input [1, 2]', (
        f"expected the exact cause naming the unresolved step and the input it could not be "
        f"applied to, got {result.get('cause')!r}: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
