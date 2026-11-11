"""update-state-machine-publish-at-version-cap-quota-exceeded."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-publish-at-version-cap-quota-exceeded"
GROUP = "update_versioning"
SERVICES = ["stepfunctions"]

_DEF = {"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}}

# Publishing a version is throttled to roughly one every couple of seconds once a short burst
# is spent, so driving a state machine to its documented 1000-version cap needs this much room.
_PUBLISH_LOOP_DEADLINE_S = 2400.0


_SFN_TRUST_POLICY = json.dumps(
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


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable role this check creates and deletes."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, timeout_s=90.0):
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue

        def _delete_sm():
            try:
                sfn.delete_state_machine(stateMachineArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                    raise

        ctx.on_cleanup(_delete_sm)
        return arn
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _publish_one(sfn, arn, role_arn, description, *, deadline):
    """UpdateStateMachine(publish=True) with a fresh description, retrying ThrottlingException."""
    while True:
        try:
            return sfn.update_state_machine(
                stateMachineArn=arn,
                definition=json.dumps(_DEF),
                roleArn=role_arn,
                publish=True,
                versionDescription=description,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ThrottlingException":
                raise
            if time.monotonic() > deadline:
                raise AssertionError("still throttled on UpdateStateMachine at the loop deadline")
            time.sleep(1.1)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Publishing a state machine version once it sits at the documented 1000-version cap is
    rejected with ServiceQuotaExceededException and its exact message, and no new version is
    created by the rejected call.

    Reference: https://docs.aws.amazon.com/step-functions/latest/apireference/API_PublishStateMachineVersion.html
    """
    sfn = ctx.client("stepfunctions")
    role = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _create_state_machine(ctx, _DEF, role, name=name)

    deadline = time.monotonic() + _PUBLISH_LOOP_DEADLINE_S
    published = 0
    quota_exc = None
    while quota_exc is None:
        published += 1
        try:
            resp = _publish_one(sfn, arn, role, f"sim2real-cap-probe-{published}", deadline=deadline)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            quota_exc = exc
            published -= 1
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"published {published} version(s) without reaching the quota before the deadline"
            )

    # Positive control: every one of the `published` versions up to the cap actually went
    # through, most recently the one immediately below the cap.
    assert published >= 900, (
        f"expected to approach the documented 1000-version cap before the rejection, "
        f"only published {published}"
    )
    assert resp["stateMachineVersionArn"] == f"{arn}:{published}", (
        f"expected the last accepted publish to mint version {published}, got {resp['stateMachineVersionArn']!r}"
    )

    code = quota_exc.response["Error"]["Code"]
    message = quota_exc.response["Error"]["Message"]
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code}"
    expected_message = f"Limit on maximum number of versions for state machine {name} reached"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected publish must not have minted version `published + 1`.
    rejected_version_arn = f"{arn}:{published + 1}"
    try:
        sfn.describe_state_machine(stateMachineArn=rejected_version_arn)
    except ClientError as exc:
        absent_code = exc.response["Error"]["Code"]
        absent_message = exc.response["Error"]["Message"]
    else:
        raise AssertionError(f"version {rejected_version_arn!r} must not exist after a rejected publish")
    assert absent_code == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist describing the never-created version, got {absent_code}"
    )
    expected_absent_message = f"State Machine Version Does Not Exist: '{rejected_version_arn}'"
    assert absent_message == expected_absent_message, (
        f"expected message {expected_absent_message!r}, got {absent_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
