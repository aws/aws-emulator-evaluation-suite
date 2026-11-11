"""get-identity-pool-roles-unauthorized-for-foreign-pool."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-unauthorized-for-foreign-pool"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIdentityPoolRoles from a zero-permission IAM user is refused with AccessDeniedException,
    and granting exactly that action on exactly that pool makes the identical call succeed.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    pool_id = _create_pool(ctx)
    pool_arn = _pool_arn(ctx, pool_id)

    # Positive control, before anything is broken: the pool's actual owner can read it.
    owner_seen = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert owner_seen["IdentityPoolId"] == pool_id, (
        f"positive control: expected GetIdentityPoolRoles to echo {pool_id!r}, got {owner_seen!r}"
    )

    # Break exactly one thing: a brand-new IAM principal with zero attached permissions. This is a
    # same-account proxy; a pool owned by another account would need a second AWS account.
    unauthorized_ci, user_name = _no_permission_client(ctx, "cognito-identity")

    code, message = _refusal(
        lambda: unauthorized_ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a zero-permission caller, got {code!r}: {message!r}"
    )
    assert message == (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"cognito-identity:GetIdentityPoolRoles on resource: {pool_arn} because no "
        "identity-based policy allows the cognito-identity:GetIdentityPoolRoles action"
    ), message

    # Restore: grant exactly this action on exactly this pool, and demand the IDENTICAL call now
    # succeeds -- proving the earlier denial was specifically the missing IAM grant, not something
    # about the pool or about this caller identity in general.
    policy_name = "sim2real-allow-get-roles"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "cognito-identity:GetIdentityPoolRoles",
                        "Resource": pool_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    restored = _poll_until(
        lambda: _outcome(lambda: unauthorized_ci.get_identity_pool_roles(IdentityPoolId=pool_id)),
        lambda c: c == "SUCCESS",
        timeout_s=90.0,
        interval_s=3.0,
        description="the newly-granted policy to take effect for the identical call",
    )
    assert restored == "SUCCESS", (
        f"granting cognito-identity:GetIdentityPoolRoles on {pool_arn} must let the identical "
        f"call succeed, proving the earlier AccessDeniedException was the missing grant; "
        f"got {restored!r}"
    )


def _create_pool(ctx, **extra) -> str:
    ci = ctx.client("cognito-identity")
    name = extra.pop("IdentityPoolName", None) or ctx.unique_name("sim2real-behav-")
    allow_unauth = extra.pop("AllowUnauthenticatedIdentities", True)
    resp = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **extra,
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _pool_arn(ctx, pool_id: str) -> str:
    return f"arn:aws:cognito-identity:{ctx.region}:{ctx.account}:identitypool/{pool_id}"


def _no_permission_client(ctx, service_name: str):
    """Create a brand-new IAM user with no attached policies and return a client for
    ``service_name`` authenticated as that user (implicit-deny on every action), plus the user
    name so the caller can later grant it a specific permission."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-noperm-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key["AccessKeyId"])
    )

    creds = {
        "aws_access_key_id": access_key["AccessKeyId"],
        "aws_secret_access_key": access_key["SecretAccessKey"],
    }

    # New IAM credentials are eventually consistent; poll (bounded) until they authenticate.
    # GetCallerIdentity requires no IAM permission, so this isolates "key active" from
    # "action authorized".
    probe = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + 30.0
    authenticated = False
    while time.monotonic() < deadline:
        try:
            probe.get_caller_identity()
            authenticated = True
            break
        except ClientError:
            time.sleep(1.5)
    if not authenticated:
        raise AssertionError("new IAM access key never became usable for authentication")

    return ctx.client(service_name, creds=creds), user_name


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _outcome(fn):
    """Call fn(); return "SUCCESS", or the refusal's Code while the grant has not propagated."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return "SUCCESS"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
