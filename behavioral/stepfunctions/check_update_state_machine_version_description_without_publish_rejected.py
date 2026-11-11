"""update-state-machine-version-description-without-publish-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-version-description-without-publish-rejected"
GROUP = "negative-classes"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_DEF_V1 = {"StartAt": "Initial", "States": {"Initial": {"Type": "Pass", "End": True}}}
_DEF_V2 = {"StartAt": "Updated", "States": {"Updated": {"Type": "Pass", "End": True}}}


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine with versionDescription set but publish not true is rejected
    ValidationException, leaving the state machine unchanged; the same versionDescription
    with publish=true succeeds and publishes a version.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-uvdnp-")
    created = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(_DEF_V1),
        roleArn=role_arn,
        tags=[{"key": "sim2real", "value": "1"}],
    )
    arn = created["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))

    code, message = _error(
        lambda: sfn.update_state_machine(
            stateMachineArn=arn,
            definition=json.dumps(_DEF_V2),
            publish=False,
            versionDescription="a description with no publish",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Version description can only be set when publish is true", (
        f"unexpected ValidationException message {message!r}"
    )

    unchanged = sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(unchanged["definition"]) == _DEF_V1, (
        f"rejected UpdateStateMachine must leave the definition unchanged, got "
        f"{json.loads(unchanged['definition'])!r}"
    )
    assert unchanged.get("stateMachineVersionArn") is None, (
        f"rejected UpdateStateMachine must not have published a version, "
        f"got {unchanged.get('stateMachineVersionArn')!r}"
    )

    # Positive control: identical versionDescription, but publish=true now succeeds.
    accepted = sfn.update_state_machine(
        stateMachineArn=arn,
        definition=json.dumps(_DEF_V2),
        publish=True,
        versionDescription="a description with no publish",
    )
    version_arn = accepted.get("stateMachineVersionArn")
    assert version_arn, "expected a stateMachineVersionArn when publish=true"
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))

    updated = _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=arn),
        lambda r: json.loads(r["definition"]).get("StartAt") == "Updated",
        timeout_s=30.0,
        description="updated definition visible",
    )
    assert updated["revisionId"] == accepted["revisionId"], (
        "describe revisionId must match the update's revisionId"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
