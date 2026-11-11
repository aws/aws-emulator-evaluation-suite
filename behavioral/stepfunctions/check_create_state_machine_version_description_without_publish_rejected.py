"""create-state-machine-version-description-without-publish-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-version-description-without-publish-rejected"
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

_DEF = {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}


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
    """CreateStateMachine with versionDescription set but publish not true is rejected
    ValidationException, and the same versionDescription with publish=true succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    rejected_name = ctx.unique_name("sim2real-behav-sm-vdnp-")

    code, message = _error(
        lambda: sfn.create_state_machine(
            name=rejected_name,
            definition=json.dumps(_DEF),
            roleArn=role_arn,
            publish=False,
            versionDescription="a description with no publish",
            tags=[{"key": "sim2real", "value": "1"}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Version description can only be set when publish is true", (
        f"unexpected ValidationException message {message!r}"
    )

    names = [sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert rejected_name not in names, (
        f"rejected CreateStateMachine must not have created {rejected_name!r}, but it is listed"
    )

    # Positive control: identical versionDescription, but publish=true now succeeds.
    accepted_name = ctx.unique_name("sim2real-behav-sm-vdnp-")
    created = _create_sm_retrying(
        sfn,
        name=accepted_name,
        definition=json.dumps(_DEF),
        roleArn=role_arn,
        publish=True,
        versionDescription="a description with no publish",
        tags=[{"key": "sim2real", "value": "1"}],
    )
    arn = created["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    version_arn = created["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))
    assert version_arn, "expected a stateMachineVersionArn when publish=true"

    described = sfn.describe_state_machine(stateMachineArn=arn)
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
