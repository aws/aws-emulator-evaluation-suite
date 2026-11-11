"""get-credentials-for-identity-invalid-token-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-invalid-token-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity rejects a forged/invalid third-party login token with
    NotAuthorizedException rather than vending STS credentials, while the unauthenticated
    (no Logins) flow against the very same identity keeps working."""
    cip = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=True
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-behav-cogid-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                        "ForAnyValue:StringLike": {
                            "cognito-identity.amazonaws.com:amr": "*"
                        },
                    },
                }
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    _set_roles_with_retry(
        cip, pool_id, {"authenticated": role_arn, "unauthenticated": role_arn}
    )

    identity_id = cip.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # Positive control: the unauthenticated flow (no Logins) vends real, usable STS
    # credentials -- IAM role propagation can lag, so retry briefly.
    creds = _retry_get_credentials(cip, identity_id)
    assert creds["IdentityId"] == identity_id, (
        f"positive control: expected IdentityId {identity_id!r}, got {creds['IdentityId']!r}"
    )
    assert creds["Credentials"]["AccessKeyId"], (
        "positive control: unauthenticated GetCredentialsForIdentity returned no AccessKeyId"
    )
    assert creds["Credentials"]["SecretKey"], (
        "positive control: unauthenticated GetCredentialsForIdentity returned no SecretKey"
    )

    # Break exactly one thing: an authenticated attempt carrying a forged provider token.
    err = _client_error(
        lambda: cip.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={"graph.facebook.com": "forged.not-a-real.facebook-token"},
        )
    )
    assert err == ("NotAuthorizedException", "Logins don't match. Please include at least one valid login for this identity or identity pool."), (
        f"expected NotAuthorizedException for a forged Facebook login token, got {err!r}"
    )

    # Effect absent / control still works: the same identity can still get credentials
    # via the unauthenticated flow after the rejected authenticated attempt.
    creds_after = cip.get_credentials_for_identity(IdentityId=identity_id)
    assert creds_after["IdentityId"] == identity_id, (
        f"post-rejection control: expected IdentityId {identity_id!r}, got "
        f"{creds_after['IdentityId']!r}"
    )
    assert creds_after["Credentials"]["AccessKeyId"], (
        "post-rejection control: the rejected forged-token attempt left the identity unable to "
        "get unauthenticated credentials"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a forged token real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects a forged login token, but the call SUCCEEDED and returned {result!r}"
    )


def _set_roles_with_retry(cip, pool_id, roles, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cip.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


def _retry_get_credentials(cip, identity_id, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cip.get_credentials_for_identity(IdentityId=identity_id)
        except ClientError as exc:
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
