"""delete-state-machine-version-idempotent-for-unknown-targets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-state-machine-version-idempotent-for-unknown-targets"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteStateMachineVersion is idempotent: it succeeds as a no-op for a version number never
    published on a real state machine and for a version ARN of a machine never created, and a
    version that does exist is left untouched by either call.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-delver-")
    definition = {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    sm_arn = _create_state_machine(ctx, role_arn, definition, name=name)

    real_version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    assert real_version_arn == f"{sm_arn}:1", (
        f"expected the first published version to be numbered 1, got {real_version_arn!r}"
    )

    # A version number far past the one real version ever published, on a state machine that
    # does exist.
    never_existing_version_arn = f"{sm_arn}:99"
    resp = sfn.delete_state_machine_version(stateMachineVersionArn=never_existing_version_arn)
    assert "ResponseMetadata" in resp, f"expected a plain success response, got {resp!r}"

    # A version-qualified ARN of a state machine that was never created at all.
    nonexistent_machine_version_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:"
        f"{ctx.unique_name('sim2real-behav-sm-delver-absent-')}:1"
    )
    resp = sfn.delete_state_machine_version(stateMachineVersionArn=nonexistent_machine_version_arn)
    assert "ResponseMetadata" in resp, f"expected a plain success response, got {resp!r}"

    # Positive control: the one version that does exist was never touched by either call above.
    desc = sfn.describe_state_machine(stateMachineArn=real_version_arn)
    assert desc["stateMachineArn"] == real_version_arn and desc["status"] == "ACTIVE", (
        f"real version {real_version_arn} affected by deletes against unrelated targets: {desc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
