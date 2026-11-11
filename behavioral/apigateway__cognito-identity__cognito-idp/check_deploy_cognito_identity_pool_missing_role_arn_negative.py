"""deploy-cognito-identity-pool-missing-role-arn-negative."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-identity-pool-missing-role-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity pool whose unauthenticated role ARN cannot be assumed fails GetCredentialsForIdentity with
    InvalidIdentityPoolConfigurationException, while a pool with a correctly trusted role returns credentials."""
    cid = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # --- negative: unauthenticated role ARN does not exist ---
    bad_pool_id = _create_identity_pool(ctx, cid, allow_unauth=True)
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-xsvc-noexist-')}"
    cid.set_identity_pool_roles(
        IdentityPoolId=bad_pool_id, Roles={"unauthenticated": bogus_role_arn}
    )
    bad_identity_id = cid.get_id(IdentityPoolId=bad_pool_id)["IdentityId"]

    expected_message = "Invalid identity pool configuration. Check assigned IAM roles for this pool."
    code, message = _error(lambda: cid.get_credentials_for_identity(IdentityId=bad_identity_id))
    assert code == "InvalidIdentityPoolConfigurationException", (
        f"expected InvalidIdentityPoolConfigurationException for a role ARN that does not "
        f"exist, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: repeating the call never yields real credentials either.
    code2, message2 = _error(lambda: cid.get_credentials_for_identity(IdentityId=bad_identity_id))
    assert code2 == "InvalidIdentityPoolConfigurationException", (
        f"expected the rejection to persist on a second identical call, got {code2!r}"
    )
    assert message2 == expected_message, (
        f"expected message {expected_message!r} on the second call, got {message2!r}"
    )

    # --- positive control: same flow, but the role genuinely exists and trusts Cognito ---
    good_pool_id = _create_identity_pool(ctx, cid, allow_unauth=True)
    role_name = ctx.unique_name("sim2real-xsvc-unauth-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": good_pool_id},
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "unauthenticated"
                    },
                },
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    good_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    cid.set_identity_pool_roles(
        IdentityPoolId=good_pool_id, Roles={"unauthenticated": good_role_arn}
    )
    good_identity_id = cid.get_id(IdentityPoolId=good_pool_id)["IdentityId"]

    # IAM role trust propagation can lag a few seconds; poll for it to become assumable.
    creds = _poll_until(
        lambda: _try_get_credentials(cid, good_identity_id),
        lambda result: result is not None,
        timeout_s=45.0,
        interval_s=3.0,
        description="get_credentials_for_identity to succeed once the role is real",
    )
    assert creds["AccessKeyId"], f"expected an AccessKeyId in the vended credentials, got {creds!r}"
    assert creds["SecretKey"], f"expected a SecretKey in the vended credentials, got {creds!r}"
    assert creds["SessionToken"], f"expected a SessionToken in the vended credentials, got {creds!r}"


def _try_get_credentials(cid, identity_id):
    try:
        return cid.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_identity_pool(ctx, cid, *, allow_unauth: bool) -> str:
    name = ctx.unique_name("sim2realxsvcidp").replace("-", "")
    pool_id = cid.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
