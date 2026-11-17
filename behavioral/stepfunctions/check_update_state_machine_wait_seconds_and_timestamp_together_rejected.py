"""update-state-machine-wait-seconds-and-timestamp-together-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-wait-seconds-and-timestamp-together-rejected"
GROUP = "definition_validation"
SERVICES = ["stepfunctions"]

_EXPECTED = ("Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: There should only be one "
             "of the following fields: [SecondsPath, Seconds, TimestampPath, Timestamp] at /States/W'")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine refuses a Wait state naming both Seconds and Timestamp with the exact
    schema message and keeps the stored definition; the same Wait with Seconds alone is applied."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    original = {"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 1, "End": True}}}
    arn = _create_state_machine(ctx, role_arn, original)

    bad = {"StartAt": "W", "States": {"W": {
        "Type": "Wait", "Seconds": 2, "Timestamp": "2026-01-01T00:00:00Z", "End": True}}}
    code, message = _error(lambda: sfn.update_state_machine(
        stateMachineArn=arn, definition=json.dumps(bad)))
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code!r}"
    assert message == _EXPECTED, f"expected {_EXPECTED!r}, got {message!r}"
    kept = sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(kept["definition"]) == original, (
        f"a refused update must keep the stored definition, got {kept['definition']!r}")

    good = {"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 2, "End": True}}}
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(good))
    applied = sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(applied["definition"]) == good, (
        f"the legal update must be stored, got {applied['definition']!r}")


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    """A role Step Functions can assume; these definitions call no other service."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnrole-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_state_machine(ctx, role_arn, definition) -> str:
    """CreateStateMachine, retrying only AccessDeniedException while the fresh role propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                     "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
