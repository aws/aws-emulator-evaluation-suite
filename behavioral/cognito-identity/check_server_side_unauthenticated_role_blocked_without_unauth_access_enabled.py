"""server-side-unauthenticated-role-blocked-without-unauth-access-enabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-unauthenticated-role-blocked-without-unauth-access-enabled"
GROUP = "server-side"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With AllowUnauthenticatedIdentities=False, anonymous GetId is rejected and creates no
    identity despite an attached unauthenticated role; the same wiring works once it is True."""
    cog = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_blocked = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cid_unauthblocked_"),
        AllowUnauthenticatedIdentities=False,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_blocked)))

    role_blocked_name = ctx.unique_name("sim2real-cid-unauth-blocked-role-")
    role_blocked_arn = _create_unauth_role(ctx, iam, pool_blocked, role_blocked_name)

    cog.set_identity_pool_roles(IdentityPoolId=pool_blocked, Roles={"unauthenticated": role_blocked_arn})

    code, message = _error(lambda: cog.get_id(IdentityPoolId=pool_blocked))
    assert code == "NotAuthorizedException", (
        f"pool has AllowUnauthenticatedIdentities=False with an unauthenticated role wired via "
        f"SetIdentityPoolRoles; expected GetId to be refused with NotAuthorizedException, got {code!r}"
    )
    assert message == "Unauthenticated access is not supported for this identity pool.", (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    listed = cog.list_identities(IdentityPoolId=pool_blocked, MaxResults=15)
    assert listed["Identities"] == [], (
        f"the refused GetId must not have allocated an identity in the blocked pool, but "
        f"list_identities returned {listed['Identities']!r}"
    )

    pool_open = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cid_unauthopen_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_open)))

    role_open_name = ctx.unique_name("sim2real-cid-unauth-open-role-")
    role_open_arn = _create_unauth_role(ctx, iam, pool_open, role_open_name)

    cog.set_identity_pool_roles(IdentityPoolId=pool_open, Roles={"unauthenticated": role_open_arn})

    identity_id = cog.get_id(IdentityPoolId=pool_open)["IdentityId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identities(IdentityIdsToDelete=[identity_id])))

    creds = _wait_for_credentials(cog, identity_id, timeout_s=60)
    assert creds["AccessKeyId"] and creds["SecretKey"] and creds["SessionToken"], (
        f"identical role/pool wiring with AllowUnauthenticatedIdentities=True must vend real STS "
        f"credentials for the anonymous identity, got {creds!r}"
    )



def _safe(fn) -> None:
    """Run a teardown call; tolerate only the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_unauth_role(ctx, iam, pool_id: str, role_name: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _wait_for_credentials(cog, identity_id: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cog.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] not in (
                "InvalidIdentityPoolConfigurationException",
                "NotAuthorizedException",
            ):
                raise
            time.sleep(3)
    raise AssertionError(f"credentials never became available: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
