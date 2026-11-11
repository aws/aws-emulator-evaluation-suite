"""concurrent-update-state-machine-conflicting-revision."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "concurrent-update-state-machine-conflicting-revision"
GROUP = "concurrency"
SERVICES = ["stepfunctions"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateStateMachine(publish=True) applies a new definition and stamps a version, a
    PublishStateMachineVersion pinned to the revisionId read before it is refused with ConflictException
    naming both revisions, and creates no version.

    Reference: https://docs.aws.amazon.com/step-functions/latest/apireference/API_PublishStateMachineVersion.html
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    sm_name = ctx.unique_name("sim2real-behav-sm-conflict-")
    def0 = json.dumps({"StartAt": "Pass0", "States": {"Pass0": {"Type": "Pass", "End": True}}})
    sm_arn = _create_state_machine(
        sfn, name=sm_name, definition=def0, role_arn=role_arn, check=CHECK
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # A fresh state machine has no revisionId; the first definition change assigns one.
    def_seed = json.dumps({"StartAt": "Pass0seed", "States": {"Pass0seed": {"Type": "Pass", "End": True}}})
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=def_seed, roleArn=role_arn)
    stale_rev = _wait_for_revision_id(sfn, sm_arn)

    new_def = json.dumps({"StartAt": "Pass1", "States": {"Pass1": {"Type": "Pass", "End": True}}})
    update = sfn.update_state_machine(stateMachineArn=sm_arn, definition=new_def, publish=True)
    version_arn = update["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: _delete_version_quiet(sfn, version_arn))
    current_rev = update["revisionId"]
    assert current_rev != stale_rev, f"UpdateStateMachine kept revisionId {stale_rev!r}"

    current_def = json.loads(sfn.describe_state_machine(stateMachineArn=sm_arn)["definition"])
    assert current_def == json.loads(new_def), (
        f"UpdateStateMachine's new definition was not applied: {current_def!r} != {json.loads(new_def)!r}"
    )

    code, message = _error(
        lambda: sfn.publish_state_machine_version(stateMachineArn=sm_arn, revisionId=stale_rev)
    )
    assert code == "ConflictException", f"expected ConflictException on stale revisionId, got {code}"
    expected = (
        f"Failed to publish the State Machine version for revision {stale_rev}. "
        f"The current State Machine revision is {current_rev}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    versions = sfn.list_state_machine_versions(stateMachineArn=sm_arn)["stateMachineVersions"]
    assert [v["stateMachineVersionArn"] for v in versions] == [version_arn], (
        f"expected only the version UpdateStateMachine stamped, got {versions}"
    )


def _create_state_machine(sfn, *, name: str, definition: str, role_arn: str, check: str):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates -- a bounded wait with a reason, not a blind sleep."""
    from botocore.exceptions import ClientError

    deadline = time.time() + 90.0
    last_err = None
    while time.time() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": check}],
            )
            return resp["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


def _wait_for_revision_id(sfn, sm_arn: str, timeout: float = 30.0, interval: float = 2.0) -> str:
    """revisionId is populated asynchronously after the first UpdateStateMachine call --
    describe_state_machine may briefly omit the field even though the prior call itself already
    succeeded. Poll for it instead of assuming it is immediately present."""
    deadline = time.time() + timeout
    while True:
        desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
        if "revisionId" in desc:
            return desc["revisionId"]
        if time.time() >= deadline:
            raise AssertionError(
                f"revisionId never appeared on {sm_arn} within {timeout}s"
            )
        time.sleep(interval)


def _error(call):
    """(code, message) of a call that must be refused; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_version_quiet(sfn, version_arn: str) -> None:
    from botocore.exceptions import ClientError

    sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
