"""sfn-create-state-machine-without-passrole-grant-is-denied."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-create-state-machine-without-passrole-grant-is-denied"
GROUP = "overly_permissive"
SERVICES = ["stepfunctions"]

_SESSION_NAME = "sim2real-behav-restricted"

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c7",
    "plane:control",
)
def run(ctx) -> None:
    """CreateStateMachine with no iam:PassRole statement at all (not an explicit deny) is
    refused with the implicit-deny wording, and nothing is created; a caller granted the
    missing permission from the start can create the identical state machine.
    """
    sfn = ctx.client("stepfunctions")
    account_id = ctx.account

    target_role_arn = _create_role(ctx, "sim2real-behav-targetrole-", _STATES_TRUST)

    caller_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": account_id},
            "Action": "sts:AssumeRole",
        }],
    })
    # No statement, Allow or Deny, mentions iam:PassRole.
    deny_role_arn, deny_role_name = _create_caller_role(ctx, caller_trust, [
        {"Effect": "Allow", "Action": "states:CreateStateMachine", "Resource": "*"},
    ])
    # A SEPARATE role, granted the missing permission from the moment it is created: updating
    # the denied role's own policy in place leaves iam:PassRole visible to a fresh AssumeRole
    # session but not to the states:CreateStateMachine authorization path for many minutes, so
    # the positive control needs its own role rather than a policy update to this one.
    allow_role_arn, _ = _create_caller_role(ctx, caller_trust, [
        {"Effect": "Allow", "Action": "states:CreateStateMachine", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": target_role_arn},
    ])

    partition = deny_role_arn.split(":")[1]
    deny_sfn = _assume_as_client(ctx, "stepfunctions", deny_role_arn)
    deny_name = ctx.unique_name("sim2real-behav-sm-deny-")
    expected_deny_arn = (
        f"arn:{partition}:states:{ctx.region}:{account_id}:stateMachine:{deny_name}"
    )
    expected_message = (
        f"User: arn:{partition}:sts::{account_id}:assumed-role/{deny_role_name}/{_SESSION_NAME} "
        f"is not authorized to perform: iam:PassRole on resource: {target_role_arn} "
        "because no identity-based policy allows the iam:PassRole action"
    )
    # Retried on the MESSAGE, not just the code: while the states:CreateStateMachine grant is
    # still propagating the caller has neither permission, and the denial names
    # states:CreateStateMachine instead -- a transient message this check must not settle on.
    error = _error_until(
        lambda: _delete_on_cleanup(ctx, sfn, deny_sfn.create_state_machine(
            name=deny_name, definition=_DEFINITION, roleArn=target_role_arn,
        )),
        settled=lambda err: err.get("Code") == "AccessDeniedException"
        and "iam:PassRole" in (err.get("Message") or ""),
    )
    assert error.get("Code") == "AccessDeniedException", (
        f"creating a state machine with no iam:PassRole grant on the role returned {error!r}, "
        f"expected AccessDeniedException"
    )
    assert error.get("Message") == expected_message, (
        f"expected AccessDeniedException message {expected_message!r}, got {error.get('Message')!r}"
    )

    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=expected_deny_arn))
    assert code == "StateMachineDoesNotExist", (
        f"the denied CreateStateMachine still left {expected_deny_arn!r} behind: describe "
        f"returned {code}: {message!r}, expected StateMachineDoesNotExist"
    )

    # Positive control: the identical call, from a caller granted iam:PassRole from the start,
    # succeeds.
    allow_sfn = _assume_as_client(ctx, "stepfunctions", allow_role_arn)
    allow_name = ctx.unique_name("sim2real-behav-sm-allow-")
    expected_allow_arn = (
        f"arn:{partition}:states:{ctx.region}:{account_id}:stateMachine:{allow_name}"
    )
    created = _retry_while_denied(
        lambda: allow_sfn.create_state_machine(
            name=allow_name, definition=_DEFINITION, roleArn=target_role_arn,
        )
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=created["stateMachineArn"]))
    assert created["stateMachineArn"] == expected_allow_arn, (
        f"the permitted create returned {created['stateMachineArn']!r}, expected "
        f"{expected_allow_arn!r}"
    )

    described = sfn.describe_state_machine(stateMachineArn=created["stateMachineArn"])
    assert described["roleArn"] == target_role_arn, (
        f"the created state machine's role is {described['roleArn']!r}, expected {target_role_arn!r}"
    )


def _delete_on_cleanup(ctx, sfn, resp):
    """Registers deletion of the state machine a create unexpectedly made, then returns it."""
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return resp


def _create_role(ctx, prefix, trust_policy):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description="sim2real-behav sfn authorisation-boundary role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_caller_role(ctx, trust_policy, statements):
    """A fresh assumable role, with `statements` as its inline policy from the moment it is
    created. Returns (role_arn, role_name)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-restrictedcaller-")
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
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn, role_name


def _assume_as_client(ctx, service, role_arn, *, timeout_s=90.0):
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _error_until(fn, *, settled, timeout_s=360.0):
    """The botocore Error dict `fn` raises once `settled(error)` is true; the last error seen
    on timeout. Raises if the call ever succeeds: the create must be refused."""
    deadline = time.monotonic() + timeout_s
    error = {}
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            error = exc.response["Error"]
            if settled(error):
                return error
            time.sleep(2)
            continue
        raise AssertionError(
            "CreateStateMachine succeeded with no iam:PassRole grant on the role; a caller "
            "without iam:PassRole on the role cannot create a state machine with it"
        )
    return error


def _retry_while_denied(fn, *, timeout_s=360.0):
    """The result of `fn`, retried while a just-created role's grants have not propagated
    (AccessDeniedException) or a just-minted session token is not yet recognised everywhere
    (UnrecognizedClientException); any other error or a timeout is a real failure."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"still denied after {timeout_s}s of IAM propagation: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
