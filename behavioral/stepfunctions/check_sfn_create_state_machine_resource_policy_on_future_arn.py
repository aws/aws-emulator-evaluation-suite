"""sfn-create-state-machine-resource-policy-on-future-arn."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-create-state-machine-resource-policy-on-future-arn"
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
    """CreateStateMachine is authorized against the ARN its own `name` parameter would mint,
    even though the state machine does not exist yet: an exact or prefix-matched ARN can be
    Denied or Allowed by name, and a name matching no statement is denied by default.
    """
    sfn = ctx.client("stepfunctions")
    account_id = ctx.account

    exec_role_arn = _create_role(ctx, "sim2real-behav-execrole-", _STATES_TRUST)

    exact_deny_name = ctx.unique_name("sim2real-behav-futarn-exactdeny-")
    prefix_deny_base = ctx.unique_name("sim2real-behav-futarn-prefixdeny-")
    exact_allow_name = ctx.unique_name("sim2real-behav-futarn-exactallow-")
    prefix_allow_base = ctx.unique_name("sim2real-behav-futarn-prefixallow-")
    unmatched_name = ctx.unique_name("sim2real-behav-futarn-unmatched-")

    def _sm_arn(name: str) -> str:
        return f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:{name}"

    # The baseline Allow excludes every name under test (NotResource), so only the
    # Allow/Deny statements below decide the outcome for each of them.
    patterns_under_test = [
        _sm_arn(exact_deny_name), _sm_arn(prefix_deny_base + "*"),
        _sm_arn(exact_allow_name), _sm_arn(prefix_allow_base + "*"),
        _sm_arn(unmatched_name),
    ]
    statements = [
        {"Effect": "Allow", "Action": "states:CreateStateMachine", "NotResource": patterns_under_test},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
        {"Effect": "Deny", "Action": "states:CreateStateMachine", "Resource": _sm_arn(exact_deny_name)},
        {"Effect": "Deny", "Action": "states:CreateStateMachine", "Resource": _sm_arn(prefix_deny_base + "*")},
        {"Effect": "Allow", "Action": "states:CreateStateMachine", "Resource": _sm_arn(exact_allow_name)},
        {"Effect": "Allow", "Action": "states:CreateStateMachine", "Resource": _sm_arn(prefix_allow_base + "*")},
    ]

    caller_role_arn, caller_role_name = _create_caller_role(ctx, account_id, statements)
    restricted_sfn = _assume_as_client(ctx, "stepfunctions", caller_role_arn)
    partition = caller_role_arn.split(":")[1]
    assumed_arn = f"arn:{partition}:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME}"

    def _create(name: str):
        return restricted_sfn.create_state_machine(
            name=name, definition=_DEFINITION, roleArn=exec_role_arn,
        )

    def _expect_denied_by_name(name: str) -> None:
        # Called only after an allow-by-pattern call has already succeeded (below), so the
        # whole policy document -- deny statements included -- is already visible: no
        # propagation retry needed here.
        code, message = _error(lambda: _create(name))
        assert code == "AccessDeniedException", (
            f"CreateStateMachine(name={name!r}) returned {code}: {message!r}, expected "
            f"AccessDeniedException"
        )
        expected = (
            f"User: {assumed_arn} is not authorized to perform: states:CreateStateMachine on "
            f"resource: {_sm_arn(name)} with an explicit deny in an identity-based policy"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        code, _ = _error(lambda: sfn.describe_state_machine(stateMachineArn=_sm_arn(name)))
        assert code == "StateMachineDoesNotExist", (
            f"a denied CreateStateMachine still left {_sm_arn(name)!r} behind: describe "
            f"returned {code}"
        )

    def _expect_allowed_by_name(name: str) -> None:
        created = _retry_while_denied(lambda: _create(name))
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=created["stateMachineArn"]))
        assert created["stateMachineArn"] == _sm_arn(name), (
            f"create returned {created['stateMachineArn']!r}, expected {_sm_arn(name)!r}"
        )
        described = sfn.describe_state_machine(stateMachineArn=created["stateMachineArn"])
        assert described["roleArn"] == exec_role_arn, (
            f"created state machine's role is {described['roleArn']!r}"
        )

    # Establish that the allow-by-pattern path is live before trusting any denial's exact
    # wording: a caller still waiting on propagation would deny everything for the wrong reason.
    _expect_allowed_by_name(exact_allow_name)
    _expect_allowed_by_name(prefix_allow_base + "-suffix")

    _expect_denied_by_name(exact_deny_name)
    _expect_denied_by_name(prefix_deny_base + "-suffix")

    # A name matching none of the authored patterns: denied by the absence of any Allow, not
    # by an explicit Deny.
    code, message = _error(lambda: _create(unmatched_name))
    assert code == "AccessDeniedException", (
        f"CreateStateMachine(name={unmatched_name!r}) returned {code}: {message!r}, expected "
        f"AccessDeniedException"
    )
    expected = (
        f"User: {assumed_arn} is not authorized to perform: states:CreateStateMachine on "
        f"resource: {_sm_arn(unmatched_name)} because no identity-based policy allows the "
        "states:CreateStateMachine action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code, _ = _error(lambda: sfn.describe_state_machine(stateMachineArn=_sm_arn(unmatched_name)))
    assert code == "StateMachineDoesNotExist", (
        f"a denied CreateStateMachine still left {_sm_arn(unmatched_name)!r} behind: describe "
        f"returned {code}"
    )


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


def _create_caller_role(ctx, account_id, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-restrictedcaller-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sts:AssumeRole",
            }],
        }),
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


def _retry_while_denied(fn, *, timeout_s=360.0):
    """The result of `fn`, retried while the freshly attached policy has not propagated
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
