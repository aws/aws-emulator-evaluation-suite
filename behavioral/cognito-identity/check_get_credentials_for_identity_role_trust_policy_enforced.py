"""get-credentials-for-identity-role-trust-policy-enforced."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-role-trust-policy-enforced"
GROUP = "server-side"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity is refused with InvalidIdentityPoolConfigurationException and the
    exact message with no role and with a role whose trust policy does not admit the pool; a
    correctly trusted role vends credentials that STS resolves to it."""
    cognito = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    pool_id = _create_pool(ctx)
    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: cognito.delete_identities(IdentityIdsToDelete=[identity_id]))

    # (1) No roles configured at all -> InvalidIdentityPoolConfigurationException
    err = _client_error(lambda: cognito.get_credentials_for_identity(IdentityId=identity_id))
    assert err == (
        "InvalidIdentityPoolConfigurationException",
        "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
    ), f"expected InvalidIdentityPoolConfigurationException with no roles configured, got {err!r}"

    # (2) A role whose trust policy does not admit cognito-identity.amazonaws.com: SetIdentityPoolRoles
    #     accepts the ARN, but the underlying AssumeRoleWithWebIdentity fails with the same
    #     InvalidIdentityPoolConfigurationException.
    untrusted_role_arn = _create_role(ctx, iam, trust_principal={"Service": "ec2.amazonaws.com"})
    cognito.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": untrusted_role_arn})
    err = _poll_until(
        lambda: _client_error(lambda: cognito.get_credentials_for_identity(IdentityId=identity_id)),
        lambda e: e[0] == "InvalidIdentityPoolConfigurationException",
        timeout_s=30, interval_s=3,
    )
    assert err == ("InvalidIdentityPoolConfigurationException", "Invalid identity pool configuration. Check assigned IAM roles for this pool."), (
        f"expected InvalidIdentityPoolConfigurationException for untrusted role, got {err!r}"
    )

    # (3) A role whose trust policy correctly permits this pool -> credentials flow end to end.
    trusted_role_arn = _create_cognito_role(ctx, iam, pool_id, amr="unauthenticated")
    cognito.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": trusted_role_arn})
    creds = _poll_until(
        lambda: _try_get_credentials(cognito, identity_id),
        lambda c: c is not None,
        timeout_s=90, interval_s=5,
    )
    assert creds["AccessKeyId"] and creds["SecretKey"] and creds["SessionToken"]
    assert creds["Expiration"] is not None

    # Independent read at the destination: prove the vended credentials are not just
    # well-formed fields on GetCredentialsForIdentity's own response, but actually work
    # against real STS and resolve to the trusted role we configured.
    caller = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    ).get_caller_identity()
    assert caller["Account"] == account_id, (
        f"vended credentials resolve to account {caller['Account']!r}, expected {account_id!r}"
    )
    trusted_role_name = trusted_role_arn.split("/")[-1]
    assert trusted_role_name in caller["Arn"], (
        f"vended credentials assumed identity {caller['Arn']!r} doesn't reference "
        f"the trusted role {trusted_role_name!r}"
    )


def _create_pool(ctx, allow_unauth: bool = True) -> str:
    cognito = ctx.client("cognito-identity")
    resp = cognito.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool"),
        AllowUnauthenticatedIdentities=allow_unauth,
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_role(ctx, iam, trust_principal: dict) -> str:
    name = ctx.unique_name("sim2real-behav-role")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": trust_principal,
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_doc))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_cognito_role(ctx, iam, pool_id: str, amr: str = "unauthenticated") -> str:
    name = ctx.unique_name("sim2real-behav-cirole")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
            },
        }],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_doc))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _try_get_credentials(cognito, identity_id: str):
    try:
        return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
    except ClientError:
        return None


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 1.0,
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
