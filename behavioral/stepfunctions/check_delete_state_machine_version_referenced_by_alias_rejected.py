"""delete-state-machine-version-referenced-by-alias-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-state-machine-version-referenced-by-alias-rejected"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStateMachineVersion on a version an alias routes to fails with ConflictException and the
    exact message and leaves its definition intact; an unreferenced version deletes, and once the
    alias is removed the same delete succeeds and the version is gone."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEF_V1)
    sfn = ctx.client("stepfunctions")

    # Positive control: deleting a version with no alias referencing it succeeds. Without
    # this, "rejects a version pinned by an alias" is indistinguishable from "rejects every
    # DeleteStateMachineVersion call".
    control_version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    sfn.delete_state_machine_version(stateMachineVersionArn=control_version_arn)
    _wait_gone(sfn, control_version_arn)

    # Break: publish the subject version and pin it into an alias's routing configuration.
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_V2))
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    alias_name = ctx.unique_name("sim2real-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name,
        routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)))

    code, message = _error(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = _conflict_message(alias_name)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected delete must not have touched the version -- it is still
    # fully intact (definition matches what was published), not merely "still describable".
    still_alive = sfn.describe_state_machine(stateMachineArn=version_arn)
    assert json.loads(still_alive["definition"]) == _DEF_V2, (
        f"version definition changed after a REJECTED delete: {still_alive}"
    )

    # Restore: remove the routing reference that caused the conflict.
    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)

    # The identical delete call now succeeds, and the version is actually gone.
    sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)
    _wait_gone(sfn, version_arn)


_DEF_V1 = {
    "Comment": "v1",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v1", "End": True}},
}
_DEF_V2 = {
    "Comment": "v2",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v2", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _conflict_message(alias_name):
    return (
        "Version to be deleted must not be referenced by an alias. "
        f"Current list of aliases referencing this version: [{alias_name}]"
    )


def _wait_gone(sfn, version_arn, *, timeout_s=60.0, interval_s=2.0):
    """DeleteStateMachineVersion is asynchronous: DescribeStateMachine on the version ARN can
    keep succeeding briefly after the delete call returns, so poll for the specific
    StateMachineDoesNotExist error instead of asserting immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=version_arn)
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "StateMachineDoesNotExist":
                raise AssertionError(f"expected StateMachineDoesNotExist for {version_arn}, got {last_code}")
            message = exc.response["Error"].get("Message")
            expected = f"State Machine Version Does Not Exist: '{version_arn}'"
            assert message == expected, f"expected message {expected!r}, got {message!r}"
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"{version_arn} still describable {timeout_s}s after delete; last error code={last_code!r}"
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
