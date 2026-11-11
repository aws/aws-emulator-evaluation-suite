"""untrusted-role-accepted-then-credentials-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untrusted-role-accepted-then-credentials-denied"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _cognito_trust_policy(pool_id, amr=None):
    condition = {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}}
    if amr:
        condition["ForAnyValue:StringLike"] = {"cognito-identity.amazonaws.com:amr": amr}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": condition,
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _client_from_credentials(ctx, service, creds):
    """Build a client signed with the vended temporary credentials."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretKey"],
        "aws_session_token": creds["SessionToken"],
    })


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles accepts a role whose trust policy excludes cognito-identity, but the
    vend fails with InvalidIdentityPoolConfigurationException; fixing only the trust policy makes
    the same configuration vend, so trust is enforced at vend time, not at role assignment.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = _create_identity_pool(ci, ctx, allow_unauth=True)
    good_trust = _cognito_trust_policy(pool_id)
    _, auth_arn = _create_role(iam, ctx, good_trust, "auth")

    # Same shape, wrong principal: only ec2 may assume this one.
    ec2_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    untrusted_name, untrusted_arn = _create_role(iam, ctx, ec2_trust, "untrusted")

    roles = {"authenticated": auth_arn, "unauthenticated": untrusted_arn}
    # SetIdentityPoolRoles does not evaluate the trust policy; only the vend does.
    deadline = time.time() + 180.0
    while True:
        try:
            ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            transient = (
                "AccessDenied", "AccessDeniedException", "ThrottlingException",
                "TooManyRequestsException", "ConcurrentModificationException",
            )
            if code in transient and time.time() < deadline:
                time.sleep(3.0)
                continue
            raise AssertionError(
                "SetIdentityPoolRoles must accept a same-account role regardless of its trust "
                f"policy (validation is lazy), but it failed with {code!r}: "
                f"{exc.response.get('Error', {}).get('Message')!r}"
            ) from exc

    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert stored["Roles"].get("unauthenticated") == untrusted_arn, (
        f"the untrusted role must be persisted verbatim, got {stored['Roles']!r}"
    )

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    try:
        response = ci.get_credentials_for_identity(IdentityId=identity_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            "GetCredentialsForIdentity must fail when the mapped role does not trust "
            f"cognito-identity, but it vended {response.get('Credentials', {}).get('AccessKeyId')!r} "
            f"for role {untrusted_name}"
        )
    expected_code = "InvalidIdentityPoolConfigurationException"
    expected_message = "Invalid identity pool configuration. Check assigned IAM roles for this pool."
    assert code == expected_code, (
        f"expected {expected_code} when the mapped role refuses cognito-identity, got {code!r}: "
        f"{message!r}"
    )
    assert message == expected_message, (
        f"expected the message {expected_message!r} when the mapped role refuses "
        f"cognito-identity, got {message!r}"
    )

    # Repair exactly one thing: the trust policy. Nothing about the pool changes.
    iam.update_assume_role_policy(RoleName=untrusted_name, PolicyDocument=good_trust)
    creds = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=180.0,
        description="the vend to succeed once the role trusts cognito-identity",
    )["Credentials"]
    caller_arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{untrusted_name}/" in caller_arn, (
        f"after the trust-policy repair the vend must assume {untrusted_name}, got {caller_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
