"""create-state-machine-already-exists-publish-state-mismatch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-already-exists-publish-state-mismatch"
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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _list_versions(sfn, sm_arn):
    out = []
    next_token = None
    while True:
        kwargs = {"stateMachineArn": sm_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        page = sfn.list_state_machine_versions(**kwargs)
        out.extend(v["stateMachineVersionArn"] for v in page["stateMachineVersions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A repeated CreateStateMachine differing only in publish state, or in versionDescription
    under publish=true, is rejected StateMachineAlreadyExists naming which mismatch caused it,
    and creates no second version.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # true-then-false: created with publish=true, repeated with publish=false.
    name_tf = ctx.unique_name("sim2real-behav-sm-tf-")
    created_tf = _create_sm_retrying(
        sfn, name=name_tf, definition=json.dumps(_DEF), roleArn=role_arn,
        publish=True, versionDescription="v1",
        tags=[{"key": "sim2real", "value": "1"}],
    )
    arn_tf = created_tf["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn_tf))
    version_tf = created_tf["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_tf))

    code, message = _error(
        lambda: sfn.create_state_machine(
            name=name_tf, definition=json.dumps(_DEF), roleArn=role_arn, publish=False,
        )
    )
    assert code == "StateMachineAlreadyExists", f"true-then-false: expected StateMachineAlreadyExists, got {code!r}"
    assert message == (
        "State Machine Already Exists: This state machine was already created with a "
        "published version."
    ), f"true-then-false: unexpected message {message!r}"
    assert _list_versions(sfn, arn_tf) == [version_tf], (
        "true-then-false: the rejected repeat must not have created a second version"
    )

    # false-then-true: created with publish=false, repeated with publish=true.
    name_ft = ctx.unique_name("sim2real-behav-sm-ft-")
    created_ft = _create_sm_retrying(
        sfn, name=name_ft, definition=json.dumps(_DEF), roleArn=role_arn, publish=False,
        tags=[{"key": "sim2real", "value": "1"}],
    )
    arn_ft = created_ft["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn_ft))

    code, message = _error(
        lambda: sfn.create_state_machine(
            name=name_ft, definition=json.dumps(_DEF), roleArn=role_arn, publish=True,
            versionDescription="v1",
        )
    )
    assert code == "StateMachineAlreadyExists", f"false-then-true: expected StateMachineAlreadyExists, got {code!r}"
    assert message == (
        "State Machine Already Exists: This state machine was already created without a "
        "published version. Please use PublishStateMachineVersion to publish a version."
    ), f"false-then-true: unexpected message {message!r}"
    assert _list_versions(sfn, arn_ft) == [], (
        "false-then-true: the rejected repeat must not have created a version"
    )

    # true-then-true with another description: same publish=true, different versionDescription.
    name_tt = ctx.unique_name("sim2real-behav-sm-tt-")
    created_tt = _create_sm_retrying(
        sfn, name=name_tt, definition=json.dumps(_DEF), roleArn=role_arn,
        publish=True, versionDescription="v1",
        tags=[{"key": "sim2real", "value": "1"}],
    )
    arn_tt = created_tt["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn_tt))
    version_tt = created_tt["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_tt))

    code, message = _error(
        lambda: sfn.create_state_machine(
            name=name_tt, definition=json.dumps(_DEF), roleArn=role_arn, publish=True,
            versionDescription="v2-different",
        )
    )
    assert code == "StateMachineAlreadyExists", f"true-then-true: expected StateMachineAlreadyExists, got {code!r}"
    assert message == (
        "State Machine Already Exists: This state machine was already created with a "
        "published version using a different description."
    ), f"true-then-true: unexpected message {message!r}"
    assert _list_versions(sfn, arn_tt) == [version_tt], (
        "true-then-true: the rejected repeat must not have created a second version"
    )

    # Positive control: the truly identical repeat (same publish, same description) is
    # idempotent, not rejected.
    idem = sfn.create_state_machine(
        name=name_tt, definition=json.dumps(_DEF), roleArn=role_arn, publish=True,
        versionDescription="v1",
    )
    assert idem["stateMachineArn"] == arn_tt, (
        f"identical repeat must be idempotent, got {idem['stateMachineArn']!r} vs {arn_tt!r}"
    )
    assert idem["stateMachineVersionArn"] == version_tt, (
        f"identical repeat must return the same version, got {idem['stateMachineVersionArn']!r} "
        f"vs {version_tt!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
