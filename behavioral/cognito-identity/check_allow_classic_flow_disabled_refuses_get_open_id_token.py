"""allow-classic-flow-disabled-refuses-get-open-id-token."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "allow-classic-flow-disabled-refuses-get-open-id-token"
GROUP = "pool-config"
SERVICES = ["cognito-identity"]

_REFUSAL_CODE = "InvalidParameterException"
_REFUSAL_MESSAGE = "Basic (classic) flow is not enabled, please use enhanced flow."
_FLIP_BUDGET_S = 180.0
_TRUST_BUDGET_S = 240.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet. Raises."""
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


def _cognito_trust_policy(pool_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                },
            },
        }],
    })


def _set_roles(ci, pool_id, roles, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """Build a fresh client signed with the vended temporary credentials.

    Credentials are handed to the constructor by value and never written into os.environ.
    """
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


# ===== check =====

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an AllowClassicFlow=False pool GetOpenIdToken is refused while the enhanced flow still
    vends; flipping the flag to True makes the same call succeed and redeem at STS.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_name = ctx.unique_name("sim2real_behav_classicoff_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        AllowClassicFlow=False,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described.get("AllowClassicFlow") is False, (
        f"DescribeIdentityPool must echo AllowClassicFlow=False, got "
        f"{described.get('AllowClassicFlow')!r}"
    )

    role_name = ctx.unique_name("sim2real-behav-classicoff-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_cognito_trust_policy(pool_id),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _set_roles(ci, pool_id, {"unauthenticated": role_arn})

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    enhanced = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=_TRUST_BUDGET_S,
        description="the enhanced flow to vend on an AllowClassicFlow=False pool",
    )["Credentials"]
    enhanced_arn = _client_from_credentials(
        ctx, "sts", enhanced
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in enhanced_arn, (
        f"control: the enhanced flow must vend {role_name}, got {enhanced_arn}"
    )

    try:
        minted = ci.get_open_id_token(IdentityId=identity_id)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        message = err.get("Message") or ""
    else:
        raise AssertionError(
            "GetOpenIdToken must be refused while AllowClassicFlow is False — the basic flow lets "
            "the client pick its own role, which is why AWS advises leaving the flag off — but it "
            f"returned a token of {len(minted.get('Token') or '')} chars for identity "
            f"{minted.get('IdentityId')!r}"
        )
    assert code == _REFUSAL_CODE, (
        f"expected {_REFUSAL_CODE} for GetOpenIdToken on an AllowClassicFlow=False "
        f"pool, got {code!r}: {message!r}"
    )
    assert message == _REFUSAL_MESSAGE, (
        f"expected message {_REFUSAL_MESSAGE!r}, got {message!r}"
    )

    still_off = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert still_off.get("AllowClassicFlow") is False, (
        f"the refused GetOpenIdToken must not have changed the pool's flag; DescribeIdentityPool "
        f"now reports {still_off.get('AllowClassicFlow')!r}"
    )
    assert ci.describe_identity(IdentityId=identity_id)["IdentityId"] == identity_id, (
        f"the refused call must leave the identity {identity_id} resolvable"
    )

    # UpdateIdentityPool replaces the whole pool, so every field is restated.
    ci.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        AllowClassicFlow=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    flipped = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert flipped.get("AllowClassicFlow") is True, (
        f"UpdateIdentityPool must set AllowClassicFlow=True, DescribeIdentityPool reports "
        f"{flipped.get('AllowClassicFlow')!r}"
    )
    token = _poll_until(
        lambda: ci.get_open_id_token(IdentityId=identity_id),
        lambda r: bool(r.get("Token")),
        timeout_s=_FLIP_BUDGET_S,
        description="GetOpenIdToken to be permitted once AllowClassicFlow is True",
    )["Token"]
    assumed = _poll_until(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName="sim2real-classic-restored",
            WebIdentityToken=token,
        ),
        lambda r: "Credentials" in r,
        timeout_s=_TRUST_BUDGET_S,
        description="the role to accept the OIDC token minted after the flag was flipped",
    )
    assert assumed["SubjectFromWebIdentityToken"] == identity_id, (
        f"STS must report the identity id as the token subject; expected {identity_id}, got "
        f"{assumed.get('SubjectFromWebIdentityToken')!r}"
    )
    assert assumed["Audience"] == pool_id, (
        f"STS must report the pool id as the audience; expected {pool_id}, got "
        f"{assumed.get('Audience')!r}"
    )
    restored_arn = _client_from_credentials(
        ctx, "sts", assumed["Credentials"]
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in restored_arn, (
        f"the restored basic flow must reach {role_name}, got {restored_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
