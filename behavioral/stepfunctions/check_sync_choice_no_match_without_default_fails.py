"""sync-choice-no-match-without-default-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-choice-no-match-without-default-fails"
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
    return json.dumps(
        {
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.kind", "StringEquals": "known", "Next": "Matched"}
                    ],
                    # deliberately NO "Default"
                },
                "Matched": {"Type": "Pass", "Result": "matched", "End": True},
            },
        }
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-syncchoice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-syncchoice-")
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
            ctx.on_cleanup(
                _teardown(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            )
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
    """A synchronous Express execution of a Choice with no Default and no matching rule reports
    status FAILED with error States.Runtime and no output, inside a successful response envelope.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    # --- Positive control: the rule matches, so the sync call succeeds. ---
    ok = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"kind": "known"}))
    assert ok["status"] == "SUCCEEDED", (
        "a matching input must report SUCCEEDED -- without this control the FAILED "
        f"assertions below cannot tell a working sync endpoint from one that answers FAILED "
        f"to everything; got {ok['status']!r} error={ok.get('error')!r}"
    )
    assert json.loads(ok["output"]) == "matched", f"expected output 'matched', got {ok['output']!r}"

    # --- The subject: no rule matches and there is no Default. ---
    try:
        bad = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"kind": "unknown"}))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a no-match Choice failure inside a successful "
            f"response carrying status=FAILED; it raised {err.get('Code')!r} instead "
            f"({err.get('Message')!r})."
        ) from exc

    assert bad["status"] == "FAILED", (
        f"a Choice with no Default and no matching rule must report status FAILED, "
        f"got {bad['status']!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"the sync response must carry error 'States.Runtime', got {bad.get('error')!r}"
    )
    cause = bad.get("cause") or ""
    assert "Failed to transition out of the state. The state does not point to a next state." in cause, (
        f"the cause must say the state could not transition; got {cause!r}"
    )
    assert "'Route'" in cause, f"the cause must name the stuck state 'Route'; got {cause!r}"
    assert "output" not in bad, (
        f"a FAILED synchronous Express execution has no output, got output={bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
