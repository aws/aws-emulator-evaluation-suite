"""sync-pass-resultpath-null-output-equals-input."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-pass-resultpath-null-output-equals-input"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]


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
    result = {"marker": "should-be-discarded", "num": 999}
    return json.dumps(
        {
            "Comment": "a Pass whose ResultPath is null beside one whose ResultPath replaces",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.mode", "StringEquals": "replace", "Next": "Replace"}
                    ],
                    "Default": "Discard",
                },
                "Discard": {
                    "Type": "Pass",
                    "Result": result,
                    "ResultPath": None,
                    "End": True,
                },
                "Replace": {
                    "Type": "Pass",
                    "Result": result,
                    "End": True,
                },
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnrpnull-role-")
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
    name = ctx.unique_name("sim2real-behav-sfnrpnull-")
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A synchronous Express Pass state with ResultPath null discards its Result, so the
    execution output equals the original input verbatim, byte for byte.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    original_input = {
        "keep": {"a": 1, "b": [1, 2, 3], "mode": "discard"},
        "flag": True,
        "mode": "discard",
    }

    # --- The subject: ResultPath null discards the Result entirely -----------------
    discarded = sfn.start_sync_execution(
        stateMachineArn=sm_arn, input=json.dumps(original_input)
    )
    assert discarded["status"] == "SUCCEEDED", (
        f"the Discard path must report SUCCEEDED, got {discarded['status']!r} "
        f"error={discarded.get('error')!r} cause={discarded.get('cause')!r}"
    )
    out = json.loads(discarded["output"])
    assert out == original_input, (
        f"ResultPath null must leave the output identical to the original input, "
        f"got {out!r} expected {original_input!r}"
    )
    assert "marker" not in json.dumps(out), (
        f"the discarded Result leaked into the output: {out!r}"
    )

    # --- Positive control: the same Result WOULD have replaced the output -----------
    replace_input = {"mode": "replace"}
    replaced = sfn.start_sync_execution(
        stateMachineArn=sm_arn, input=json.dumps(replace_input)
    )
    assert replaced["status"] == "SUCCEEDED", (
        f"the Replace path must report SUCCEEDED, got {replaced['status']!r} "
        f"error={replaced.get('error')!r} cause={replaced.get('cause')!r}"
    )
    replaced_out = json.loads(replaced["output"])
    assert replaced_out == {"marker": "should-be-discarded", "num": 999}, (
        f"without ResultPath null the default '$' ResultPath must replace the input "
        f"with the Result, got {replaced_out!r} — without this control the Discard "
        f"assertion above cannot tell a real discard from a machine that never "
        f"applies its Result at all"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
