"""deep-cognito-identity-1-unsigned-public-api-control-plane-rejected-while-credentials-vend."""
from __future__ import annotations

import json
import time

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-1-unsigned-public-api-control-plane-rejected-while-credentials-vend"
GROUP = "unsigned-public-api"
SERVICES = ["cognito-identity"]

# On real Cognito Identity, an UNSIGNED request to an operation
# the model does NOT mark `auth: []` is refused with this code (HTTP 400), for CreateIdentityPool
# and DescribeIdentityPool alike. The model declares no such error on either operation.
ERR_UNSIGNED = "MissingAuthenticationTokenException"
MSG_UNSIGNED = "Missing Authentication Token"
# The vended credentials are not usable until IAM has propagated the freshly created role.
_PROPAGATION_CODES = {"InvalidIdentityPoolConfigurationException"}


@tags(
    "dp:api",
    "plane:data",
    "concern:negative-classes",
    "concern:data-plane",
    "axis:rejection",
    "cap:c1",
)
def run(ctx) -> None:
    """An unsigned client gets credentials that assume the pool's unauthenticated role from the
    public operations, while the same client is refused the control plane and the refused
    CreateIdentityPool leaves nothing behind; a signed DescribeIdentityPool is the control."""
    signed = ctx.client("cognito-identity")
    unsigned = ctx.client("cognito-identity", config=Config(signature_version=UNSIGNED))
    iam = ctx.client("iam")
    me = ctx.client("sts").get_caller_identity()
    account = me["Account"]
    partition = me["Arn"].split(":")[1]

    pool_name = ctx.unique_name("sim2real-unsigned-pool-").replace("-", "_")
    pool_id = signed.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": GROUP},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: signed.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-unsigned-unauth-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_unauth_trust_policy(pool_id)),
        Tags=[{"Key": "sim2real", "Value": GROUP}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    signed.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    # --- the public half: unsigned GetId -> GetCredentialsForIdentity must SUCCEED -------------
    identity_id = unsigned.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert identity_id.startswith(f"{ctx.region}:"), (
        f"unsigned GetId returned {identity_id!r}, expected a '{ctx.region}:<guid>' identity id"
    )
    vended = _poll_until_success(
        lambda: unsigned.get_credentials_for_identity(IdentityId=identity_id),
        retryable_codes=_PROPAGATION_CODES, timeout_s=120.0, interval_s=3.0,
    )
    assert vended["IdentityId"] == identity_id, (
        f"GetCredentialsForIdentity answered for {vended['IdentityId']!r}, asked for {identity_id!r}"
    )
    creds = vended["Credentials"]
    as_identity = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretKey"],
        "aws_session_token": creds["SessionToken"],
    }).get_caller_identity()
    assert as_identity["Account"] == account, (
        f"vended credentials resolve to account {as_identity['Account']!r}, expected {account!r}"
    )
    want_prefix = f"arn:{partition}:sts::{account}:assumed-role/{role_name}/"
    assert as_identity["Arn"].startswith(want_prefix), (
        f"vended credentials are {as_identity['Arn']!r}; expected the unauthenticated role "
        f"session {want_prefix}*"
    )

    # --- the refused half: same unsigned client, control-plane operations ----------------------
    refused_name = ctx.unique_name("sim2real-unsigned-refused-").replace("-", "_")
    err = _create_error(ctx, signed, unsigned, refused_name)
    assert (err.get("Code"), err.get("Message")) == (ERR_UNSIGNED, MSG_UNSIGNED), (
        f"unsigned CreateIdentityPool answered {err!r}, expected {ERR_UNSIGNED!r}: {MSG_UNSIGNED!r}"
    )
    leaked = [p["IdentityPoolId"] for p in _all_pools(signed) if p["IdentityPoolName"] == refused_name]
    assert leaked == [], f"the refused unsigned CreateIdentityPool still created pool(s) {leaked!r}"

    err = _error(lambda: unsigned.describe_identity_pool(IdentityPoolId=pool_id))
    assert (err.get("Code"), err.get("Message")) == (ERR_UNSIGNED, MSG_UNSIGNED), (
        f"unsigned DescribeIdentityPool answered {err!r}, expected {ERR_UNSIGNED!r}: {MSG_UNSIGNED!r}"
    )

    # --- positive controls, same instant ---------------------------------------------------------
    described = signed.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolId"] == pool_id and described["IdentityPoolName"] == pool_name, (
        f"signed DescribeIdentityPool returned {described['IdentityPoolId']!r}/"
        f"{described['IdentityPoolName']!r}, expected {pool_id!r}/{pool_name!r}"
    )
    assert described["AllowUnauthenticatedIdentities"] is True, (
        f"AllowUnauthenticatedIdentities is {described['AllowUnauthenticatedIdentities']!r}"
    )
    again = unsigned.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert again != identity_id and again.startswith(f"{ctx.region}:"), (
        f"after the refusals an unsigned anonymous GetId returned {again!r}; expected a NEW "
        f"identity distinct from {identity_id!r}"
    )


# ===== helpers =====

def _unauth_trust_policy(pool_id):
    """The trust policy shape AWS documents for an identity pool's unauthenticated role."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
            },
        }],
    }


def _error(fn):
    """The ClientError fn() raised (Code, Message). A success is never an error: it raises instead."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    resp.pop("ResponseMetadata", None)
    raise AssertionError(f"call was expected to be refused but succeeded: {resp!r}")


def _create_error(ctx, signed, unsigned, name):
    """Unsigned CreateIdentityPool's error; if it wrongly succeeds, reap what it made."""
    try:
        resp = unsigned.create_identity_pool(IdentityPoolName=name, AllowUnauthenticatedIdentities=True)
    except ClientError as exc:
        return exc.response.get("Error", {})
    made = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: signed.delete_identity_pool(IdentityPoolId=made))
    raise AssertionError(f"unsigned CreateIdentityPool was accepted and created {made!r}")


def _all_pools(ci):
    pools, token = [], None
    while True:
        kw = {"MaxResults": 60}
        if token:
            kw["NextToken"] = token
        page = ci.list_identity_pools(**kw)
        pools.extend(page.get("IdentityPools", []))
        token = page.get("NextToken")
        if not token:
            return pools


def _poll_until_success(fn, *, retryable_codes, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in retryable_codes:
                raise
            last = exc
            time.sleep(interval_s)
    raise AssertionError(f"never succeeded within {timeout_s}s: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
