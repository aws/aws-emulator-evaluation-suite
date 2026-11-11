"""sync-resultpath-over-array-reference-path-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-resultpath-over-array-reference-path-conflict"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]

_RESULT_PATH = "$.notExist.notExist"


def _trust_policy() -> str:
    return json.dumps(
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


def _definition() -> str:
    return json.dumps(
        {
            "Comment": "ResultPath grafts onto an array input versus an object input",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.mode", "StringEquals": "array", "Next": "MakeArray"}
                    ],
                    "Default": "GraftOnObject",
                },
                "MakeArray": {
                    "Type": "Pass",
                    "Result": [1, 2],
                    "Next": "GraftOnArray",
                },
                "GraftOnArray": {
                    "Type": "Pass",
                    "Result": {"ignored": True},
                    "ResultPath": _RESULT_PATH,
                    "End": True,
                },
                "GraftOnObject": {
                    "Type": "Pass",
                    "Result": {"ignored": True},
                    "ResultPath": _RESULT_PATH,
                    "End": True,
                },
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnrpc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnrpc-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_definition(),
                roleArn=role_arn,
                type="EXPRESS",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A ResultPath that steps through an array, rather than an object, fails the
    synchronous execution with States.ReferencePathConflict naming the array verbatim.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: the identical ResultPath grafts fine onto an object -----
    ok = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"mode": "object"}))
    assert ok["status"] == "SUCCEEDED", (
        "the same ResultPath over an object input must report SUCCEEDED — without "
        f"this control the failure below cannot tell a real conflict from a machine "
        f"that rejects this ResultPath outright; got {ok['status']!r} "
        f"error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"]) == {
        "mode": "object",
        "notExist": {"notExist": {"ignored": True}},
    }, f"expected the Result grafted at {_RESULT_PATH!r}, got {ok['output']!r}"

    # --- The subject: the same ResultPath stepping through an array ----------------
    try:
        bad = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"mode": "array"}))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a ResultPath conflict inside a successful "
            f"response carrying status=FAILED; it raised {err.get('Code')!r} instead "
            f"({err.get('Message')!r})."
        ) from exc

    assert bad["status"] == "FAILED", (
        f"a ResultPath stepping through an array must report status FAILED; got {bad['status']!r}"
    )
    assert bad.get("error") == "States.ReferencePathConflict", (
        f"the sync response must carry error 'States.ReferencePathConflict'; "
        f"got {bad.get('error')!r}"
    )
    expected_cause = 'Unable to apply step "notExist" to input [1,2]'
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert "output" not in bad, (
        f"a FAILED synchronous Express execution has no output; it carried "
        f"output={bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
