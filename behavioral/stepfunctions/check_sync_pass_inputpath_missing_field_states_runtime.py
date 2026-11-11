"""sync-pass-inputpath-missing-field-states-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-pass-inputpath-missing-field-states-runtime"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]

_INPUT_PATH = "$.missing"


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
            "Comment": "a Pass state whose InputPath names a field absent from its input",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.mode", "StringEquals": "bad", "Next": "BadPass"}
                    ],
                    "Default": "GoodPass",
                },
                "GoodPass": {
                    "Type": "Pass",
                    "End": True,
                },
                "BadPass": {
                    "Type": "Pass",
                    "InputPath": _INPUT_PATH,
                    "End": True,
                },
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnipass-role-")
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
    name = ctx.unique_name("sim2real-behav-sfnipass-")
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A synchronous Express execution of a Pass state whose InputPath names a field
    absent from its own input ends FAILED with States.Runtime and AWS's exact cause.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-inputpath-params.html
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: the same machine, the Default path with no InputPath ----------
    ok = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"mode": "ok"}))
    assert ok["status"] == "SUCCEEDED", (
        "the mode=ok path (no InputPath) must report SUCCEEDED — without this control the "
        f"failure assertions below cannot tell a working sync endpoint from one that answers "
        f"FAILED to everything; got {ok['status']!r} error={ok.get('error')!r}"
    )
    assert json.loads(ok["output"]) == {"mode": "ok"}, (
        f"a Pass state with neither Result nor InputPath must echo its input verbatim, "
        f"got {ok['output']!r}"
    )

    # --- The subject: InputPath names a field the execution input lacks -------------------
    try:
        bad = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"mode": "bad"}))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report an InputPath runtime failure inside a "
            f"successful response carrying status=FAILED; it raised {err.get('Code')!r} "
            f"instead ({err.get('Message')!r})."
        ) from exc

    assert bad["status"] == "FAILED", (
        f"a Pass state whose InputPath selects an absent field must report status FAILED; "
        f"got {bad['status']!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"the sync response must carry error 'States.Runtime'; got {bad.get('error')!r}"
    )
    expected_cause = (
        "An error occurred while executing the state 'BadPass' (entered at the event "
        f"id #4). Invalid path '{_INPUT_PATH}' : No results for path: $['missing']"
    )
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
