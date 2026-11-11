"""get-credentials-without-roles-configured-fails."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-without-roles-configured-fails"
GROUP = "credentials"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_unauth_role(iam, ctx, pool_id):
    """Create a role trusted by this pool for unauthenticated identities; returns its ARN."""
    role_name = ctx.unique_name("sim2real-cog-unauth-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "unauthenticated"
                    },
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity must fail if the pool has never had SetIdentityPoolRoles called,
    and the identical call for the same identity must succeed once a role is configured — proving
    the rejection traces to the missing role mapping and not to a broken pool or account."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]

    code, status, message = _refusal(lambda: ev.get_credentials_for_identity(IdentityId=identity_id))
    assert code == "InvalidIdentityPoolConfigurationException", (
        f"expected InvalidIdentityPoolConfigurationException with no roles configured, "
        f"got {code!r}: {message!r}"
    )
    assert status == 400, f"expected HTTP 400 for the refusal, got {status!r}"
    expected_message = "Invalid identity pool configuration. Check assigned IAM roles for this pool."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # State unchanged: the refusal configured nothing and the identity still resolves.
    roles = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert not roles.get("Roles"), f"expected no Roles on the pool after the refusal, got {roles.get('Roles')!r}"
    described = ev.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, (
        f"expected DescribeIdentity to still resolve the identity after the refusal, got {described.get('IdentityId')!r}"
    )

    iam = ctx.client("iam")
    role_arn = _create_unauth_role(iam, ctx, pool_id)
    ev.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn, "authenticated": role_arn}
    )

    creds = None
    last_err = None
    deadline = time.monotonic() + 60.0
    while creds is None and time.monotonic() < deadline:
        try:
            creds = ev.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as exc:
            last_err = exc.response.get("Error", {}).get("Code")
            time.sleep(3.0)
    assert creds is not None, (
        "expected GetCredentialsForIdentity to succeed for the same identity once "
        f"SetIdentityPoolRoles configured a role (last error: {last_err})"
    )
    for key in ("AccessKeyId", "SecretKey", "SessionToken"):
        assert creds.get(key), f"the restored GetCredentialsForIdentity returned an empty Credentials.{key}"
    expiration = creds.get("Expiration")
    assert expiration is not None and expiration > datetime.now(timezone.utc), (
        f"the restored credentials expire at {expiration!r}, expected a time in the future"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
