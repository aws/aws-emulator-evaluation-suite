"""list-attached-role-policies-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-attached-role-policies-denied-without-permission"
GROUP = "error-semantics"
SERVICES = ["iam"]

_DENY_ALL_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"
_SESSION_NAME = "sim2real-batch09-denied"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A principal with no IAM permissions is denied ListAttachedRolePolicies (AccessDenied) even though the
    target role and its attached policy genuinely exist; the same call succeeds for the admin caller (positive
    control), proving the denial is an authorization boundary and not a broken/missing target."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    target_role = ctx.unique_name("sim2real-batch09-target-role-")
    iam.create_role(
        RoleName=target_role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=target_role))
    iam.attach_role_policy(RoleName=target_role, PolicyArn=_DENY_ALL_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=target_role, PolicyArn=_DENY_ALL_ARN))

    # Positive control: the admin caller can see the attachment.
    control = iam.list_attached_role_policies(RoleName=target_role)["AttachedPolicies"]
    assert len(control) == 1 and control[0]["PolicyArn"] == _DENY_ALL_ARN

    # A bare role: trust policy only, zero permission policies attached.
    caller_role_name = ctx.unique_name("sim2real-batch09-noperm-role-")
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=caller_role_name))

    restricted = _wait_for_restricted_client(ctx, sts, caller_role_arn, iam)

    # Freshly-issued temporary credentials can transiently be rejected as InvalidClientTokenId
    # while they replicate to the IAM control plane; poll past that transient window and require
    # the durable outcome to be AccessDenied.
    code, message = _poll_for_stable_code(
        lambda: restricted.list_attached_role_policies(RoleName=target_role),
        transient_codes=("InvalidClientTokenId",),
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code}"
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME}"
    expected = _with_authorization_details(
        f"User: {session_arn} is not authorized to perform: iam:ListAttachedRolePolicies on "
        f"resource: role {target_role} because no identity-based policy allows the "
        "iam:ListAttachedRolePolicies action",
        message,
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Restore: grant the identical caller the identical permission, then require the identical
    # call to succeed. Without this leg, "denied because zero permissions" is indistinguishable
    # from "denied unconditionally" -- a target that refuses every non-admin caller regardless of
    # its policies would already have passed everything above.
    grant_policy_name = "sim2real-batch09-allow-list-attached"
    iam.put_role_policy(
        RoleName=caller_role_name,
        PolicyName=grant_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:ListAttachedRolePolicies", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName=grant_policy_name))

    restored = _poll_until_allowed(
        lambda: restricted.list_attached_role_policies(RoleName=target_role)["AttachedPolicies"],
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3.0,
    )
    assert len(restored) == 1 and restored[0]["PolicyArn"] == _DENY_ALL_ARN, (
        f"expected the identical call to succeed once the caller is granted iam:ListAttachedRolePolicies, "
        f"got {restored}"
    )


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` followed by a pointer to the per-request authorization
    id, the one opaque token read back from the message; the console link names us-east-1."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _poll_for_stable_code(fn, timeout_s=30.0, interval_s=2.0, transient_codes=()):
    """``(code, message)`` once the refusal code leaves ``transient_codes``; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] not in transient_codes:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"the refusal never left {transient_codes} within {timeout_s}s; last {last!r}")


def _wait_for_restricted_client(ctx, sts, role_arn, base_iam_client, timeout_s=30.0, interval_s=2.0):
    """AssumeRole against a just-created role can transiently 403 until the trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return ctx.client(
                "iam",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s, last error: {last_code}")


def _poll_until_allowed(fn, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"expected the call to succeed within {timeout_s}s, last error: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
