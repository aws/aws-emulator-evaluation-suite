"""error-invalid-token-list-map-runs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-token-list-map-runs"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMapRuns on an existing execution with a corrupted nextToken raises InvalidToken, not
    ExecutionDoesNotExist or an empty page; the same call without a token succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-behav-sm-lmr-")
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    started = sfn.start_execution(stateMachineArn=sm_arn, input="{}")
    exec_arn = started["executionArn"]

    control = sfn.list_map_runs(executionArn=exec_arn)
    assert "mapRuns" in control, f"positive control: expected a mapRuns page, got {control!r}"

    corrupted_token = "%%%not-a-real-pagination-token%%%"
    code, message = _refusal(lambda: sfn.list_map_runs(executionArn=exec_arn, nextToken=corrupted_token))
    assert code == "InvalidToken", f"expected InvalidToken, got {code!r}"
    expected_message = "Invalid Token: 'Invalid token'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, sfn, name, definition, role_arn):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            created = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            return created["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
