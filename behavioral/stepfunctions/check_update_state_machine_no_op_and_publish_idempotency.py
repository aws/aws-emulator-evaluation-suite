"""update-state-machine-no-op-and-publish-idempotency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-no-op-and-publish-idempotency"
GROUP = "update_versioning"
SERVICES = ["stepfunctions"]

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

_DEF_1 = {"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}}
_DEF_2 = {"StartAt": "B", "States": {"B": {"Type": "Pass", "End": True}}}


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine mints a new revision and version only when the config changes;
    an unchanged definition, role or versionDescription is a no-op even with publish=True,
    which republishes the existing version instead of minting a new one."""
    sfn = ctx.client("stepfunctions")
    role = _create_sfn_role(ctx)
    arn = _create_state_machine(ctx, _DEF_1, role)
    created = sfn.describe_state_machine(stateMachineArn=arn)
    assert created.get("revisionId") is None, (
        f"expected no revisionId on a freshly created state machine, got {created.get('revisionId')!r}"
    )

    noop = sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_DEF_1), roleArn=role)
    assert noop["updateDate"] == created["creationDate"], (
        f"an update with unchanged config must report updateDate == creationDate, "
        f"got updateDate={noop['updateDate']!r} creationDate={created['creationDate']!r}"
    )
    assert noop.get("revisionId") is None, (
        f"an update with unchanged config must mint no revisionId, got {noop.get('revisionId')!r}"
    )

    pub_true = sfn.update_state_machine(
        stateMachineArn=arn, definition=json.dumps(_DEF_1), roleArn=role, publish=True
    )
    v1_arn = pub_true.get("stateMachineVersionArn")
    assert v1_arn, "publish=True on unchanged config must still return a stateMachineVersionArn"
    assert pub_true.get("revisionId") is None, (
        f"publish=True on unchanged config must mint no revisionId, got {pub_true.get('revisionId')!r}"
    )
    assert pub_true["updateDate"] == created["creationDate"], (
        "publish=True on unchanged config must still report updateDate == creationDate"
    )

    pub_false = sfn.update_state_machine(
        stateMachineArn=arn, definition=json.dumps(_DEF_1), roleArn=role, publish=False
    )
    assert pub_false.get("revisionId") == pub_true.get("revisionId"), (
        "publish=True-then-false on unchanged config must return the existing revisionId"
    )
    assert pub_false["updateDate"] == pub_true["updateDate"], (
        "publish=True-then-false on unchanged config must return the existing updateDate"
    )

    pub_true_again = sfn.update_state_machine(
        stateMachineArn=arn, definition=json.dumps(_DEF_1), roleArn=role, publish=True
    )
    assert pub_true_again.get("stateMachineVersionArn") == v1_arn, (
        f"publish=False-then-true on unchanged config must republish the existing version "
        f"{v1_arn!r}, got {pub_true_again.get('stateMachineVersionArn')!r}"
    )

    changed = sfn.update_state_machine(
        stateMachineArn=arn, definition=json.dumps(_DEF_2), roleArn=role, publish=True
    )
    changed_rev = changed.get("revisionId")
    v2_arn = changed.get("stateMachineVersionArn")
    assert changed_rev, f"a changed definition must mint a non-blank revisionId, got {changed_rev!r}"
    assert v2_arn and v2_arn != v1_arn, (
        f"a changed definition published must mint a new version distinct from {v1_arn!r}, got {v2_arn!r}"
    )

    desc_a = sfn.update_state_machine(
        stateMachineArn=arn,
        definition=json.dumps(_DEF_2),
        roleArn=role,
        publish=True,
        versionDescription="sim2real-desc-a",
    )
    desc_a_rev = desc_a.get("revisionId")
    v3_arn = desc_a.get("stateMachineVersionArn")
    assert desc_a_rev and desc_a_rev != changed_rev, (
        f"adding a versionDescription (null -> non-null) with unchanged definition/role must mint "
        f"a new revision distinct from {changed_rev!r}, got {desc_a_rev!r}"
    )
    assert v3_arn and v3_arn != v2_arn, (
        f"adding a versionDescription must mint a new version distinct from {v2_arn!r}, got {v3_arn!r}"
    )

    desc_a_again = sfn.update_state_machine(
        stateMachineArn=arn,
        definition=json.dumps(_DEF_2),
        roleArn=role,
        publish=True,
        versionDescription="sim2real-desc-a",
    )
    assert desc_a_again.get("revisionId") == desc_a_rev, (
        "an unchanged versionDescription must be idempotent on revisionId"
    )
    assert desc_a_again.get("stateMachineVersionArn") == v3_arn, (
        "an unchanged versionDescription must republish the same version"
    )

    desc_b = sfn.update_state_machine(
        stateMachineArn=arn,
        definition=json.dumps(_DEF_2),
        roleArn=role,
        publish=True,
        versionDescription="sim2real-desc-b",
    )
    desc_b_rev = desc_b.get("revisionId")
    v4_arn = desc_b.get("stateMachineVersionArn")
    assert desc_b_rev and desc_b_rev != desc_a_rev, (
        f"a different versionDescription must mint a new revision distinct from {desc_a_rev!r}, "
        f"got {desc_b_rev!r}"
    )
    assert v4_arn and v4_arn != v3_arn, (
        f"a different versionDescription must mint a new version distinct from {v3_arn!r}, got {v4_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
