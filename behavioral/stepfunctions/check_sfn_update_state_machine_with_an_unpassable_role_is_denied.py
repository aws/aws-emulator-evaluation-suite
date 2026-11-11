"""sfn-update-state-machine-with-an-unpassable-role-is-denied."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-update-state-machine-with-an-unpassable-role-is-denied"
GROUP = 'overly_permissive'
SERVICES = ['stepfunctions']

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
_UPDATED_DEFINITION = json.dumps({
    "Comment": "updated-by-restricted-caller",
    "StartAt": "Pass",
    "States": {"Pass": {"Type": "Pass", "End": True}},
})


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c7",
    "plane:control",
)
def run(ctx) -> None:
    """UpdateStateMachine that would attach a role the caller cannot pass is denied, the old
    role stays in effect, and the same caller can still change the definition.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original_role_arn = _create_role(ctx, "sim2real-behav-origrole-", _STATES_TRUST)
    # A valid execution role; the only problem is the caller's inability to pass it.
    target_role_arn = _create_role(ctx, "sim2real-behav-targetrole-", _STATES_TRUST)

    sm_arn = sfn.create_state_machine(
        name=ctx.unique_name("sim2real-behav-sm-"),
        definition=_DEFINITION,
        roleArn=original_role_arn,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    caller_role_arn = _create_role(
        ctx,
        "sim2real-behav-restrictedcaller-",
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sts:AssumeRole",
            }],
        }),
        statements=[
            {"Effect": "Allow", "Action": "states:*", "Resource": "*"},
            # UpdateStateMachine checks iam:PassRole against whatever roleArn ends up attached
            # on EVERY call, even one that passes no new role — so the current role must be
            # allowed for the positive control below to exercise the definition-only path
            # instead of tripping the same deny this check is about.
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": original_role_arn},
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": target_role_arn},
        ],
    )

    restricted_sfn = _assume_as_client(ctx, "stepfunctions", caller_role_arn)
    before = sfn.describe_state_machine(stateMachineArn=sm_arn)

    error = _error_when_settled(
        lambda: restricted_sfn.update_state_machine(
            stateMachineArn=sm_arn, roleArn=target_role_arn
        ),
        expected="AccessDeniedException",
    )
    assert error.get("Code") == "AccessDeniedException", (
        f"passing a role the caller is denied iam:PassRole on returned {error!r}, expected "
        f"AccessDeniedException"
    )
    partition = caller_role_arn.split(":")[1]
    caller_role_name = caller_role_arn.rsplit("/", 1)[-1]
    expected_message = (
        f"User: arn:{partition}:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME} "
        f"is not authorized to perform: iam:PassRole on resource: {target_role_arn} "
        "with an explicit deny in an identity-based policy"
    )
    assert error.get("Message") == expected_message, (
        f"expected AccessDeniedException message {expected_message!r}, got {error.get('Message')!r}"
    )

    denied = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert denied["roleArn"] == original_role_arn, (
        f'the rejected update changed the attached role to {denied["roleArn"]!r}; it must still '
        f"be {original_role_arn!r}"
    )
    # The whole mutable surface, not just the role: a rejected update must leave every field it
    # could have written exactly as it was.
    assert _mutable(denied) == _mutable(before), (
        f"the rejected update changed the state machine: it is now {_mutable(denied)!r}, it was "
        f"{_mutable(before)!r}"
    )

    # Positive control: the same caller can update without passing a new role. Its inline policy
    # propagates on IAM's timeline, so this is retried on AccessDeniedException.
    _retry_while_denied(
        lambda: restricted_sfn.update_state_machine(
            stateMachineArn=sm_arn, definition=_UPDATED_DEFINITION
        )
    )
    after = _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=sm_arn),
        lambda d: d["definition"] == _UPDATED_DEFINITION,
        timeout_s=60.0,
        description="the definition-only update to become visible",
    )
    assert after["roleArn"] == original_role_arn, (
        f'the definition-only update changed the role to {after["roleArn"]!r}'
    )
    assert _mutable(after) != _mutable(denied), (
        f"the control update landed nothing: the state machine is still {_mutable(after)!r}"
    )


_SESSION_NAME = "sim2real-behav-restricted"
#: Everything UpdateStateMachine can write. revisionId is absent: DescribeStateMachine omits it
#: even after PublishStateMachineVersion, and updateDate is not in the model.
_MUTABLE_FIELDS = ("definition", "roleArn", "loggingConfiguration", "tracingConfiguration")


def _mutable(described):
    return {k: described.get(k) for k in _MUTABLE_FIELDS}


def _create_role(ctx, prefix, trust_policy, *, statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description="sim2real-behav sfn authorisation-boundary role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _assume_as_client(ctx, service, role_arn, *, timeout_s=60.0):
    """A ctx client for `service` signed with `role_arn`'s credentials, same target as ctx's.
    Assuming a brand-new role fails until IAM propagates, so the retry is bounded."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
        except ClientError as exc:
            last = exc
            time.sleep(2)
            continue
        return ctx.client(
            service,
            config=Config(retries={"max_attempts": 2}),
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )
    raise AssertionError(f"could not assume {role_arn!r} within {timeout_s}s: {last!r}")


def _error_when_settled(fn, *, expected, timeout_s=60.0):
    """The botocore Error dict `fn` raises once the inline Deny has propagated; the last error
    seen on timeout. Raises if the call ever succeeds: the update must be refused."""
    deadline = time.monotonic() + timeout_s
    error = {}
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            error = exc.response["Error"]
            if error.get("Code") == expected:
                return error
            time.sleep(2)
            continue
        raise AssertionError(
            "UpdateStateMachine SUCCEEDED with a roleArn the caller is denied iam:PassRole on; "
            "real AWS refuses it, and the state machine's role has now been changed"
        )
    return error


def _retry_while_denied(fn, *, timeout_s=60.0):
    """The result of `fn`, retried while a just-attached Allow has not propagated
    (AccessDeniedException); any other error or a timeout is a real failure."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"still denied after {timeout_s}s of IAM propagation: {last!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
