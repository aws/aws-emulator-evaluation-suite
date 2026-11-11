"""trust-policy-sub-condition-admits-only-the-named-identity."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-policy-sub-condition-admits-only-the-named-identity"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]

REFUSAL_CODE = "InvalidIdentityPoolConfigurationException"
REFUSAL_MESSAGE = "Invalid identity pool configuration. Check assigned IAM roles for this pool."

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


def _sub_scoped_trust_policy(pool_id, subs):
    """Trust cognito-identity for this pool, unauthenticated guests, and ONLY these identity ids."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": pool_id,
                    "cognito-identity.amazonaws.com:sub": list(subs),
                },
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
    """A client signed with the vended temporary credentials, passed by value, never os.environ."""
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
    """A trust policy scoped by cognito-identity.amazonaws.com:sub admits only the identity ids it
    names: guest A is vended the role, guest B in the same pool is refused, and adding B admits it.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_sub_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # Both guest identities are minted BEFORE any role exists, so the role is never permissive for
    # identity B at any instant and no cached STS allow can exist for it.
    identity_a = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_a]))
    identity_b = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_b]))
    assert identity_a != identity_b, (
        f"two GetId calls with no Logins must mint two distinct guest identities, both returned "
        f"{identity_a!r} — nothing below could then distinguish them"
    )

    role_name = ctx.unique_name("sim2real-behav-subscoped-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_sub_scoped_trust_policy(pool_id, [identity_a]),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _set_roles(ci, pool_id, {"unauthenticated": role_arn})

    # ---- beat 1: positive control. The named identity is admitted, and the proof is read at STS
    # through GetCallerIdentity rather than off the vend's own response.
    creds_a = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_a),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=_TRUST_BUDGET_S,
        description="the sub-scoped role to admit the identity it names",
    )["Credentials"]
    arn_a = _client_from_credentials(ctx, "sts", creds_a).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in arn_a, (
        f"control: identity A must assume {role_name}, got {arn_a}"
    )

    # ---- beat 2 and 3: exactly one thing differs — the identity id — and the refusal is specific.
    try:
        vended_b = ci.get_credentials_for_identity(IdentityId=identity_b)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code_b = err.get("Code")
        message_b = err.get("Message") or ""
    else:
        leaked = _client_from_credentials(
            ctx, "sts", vended_b["Credentials"]
        ).get_caller_identity()["Arn"]
        raise AssertionError(
            "a trust policy naming only identity A's cognito-identity.amazonaws.com:sub must "
            f"refuse identity B, but B was vended {vended_b['Credentials']['AccessKeyId']!r} "
            f"acting as {leaked}"
        )
    assert code_b == REFUSAL_CODE, (
        f"expected {REFUSAL_CODE} for an identity absent from the sub condition, "
        f"got {code_b!r}: {message_b!r}"
    )
    assert message_b == REFUSAL_MESSAGE, (
        f"expected the refusal message {REFUSAL_MESSAGE!r}, got {message_b!r}"
    )

    # ---- beat 4: the effect is absent. DescribeIdentity is an independent read: identity B must
    # still exist and be unchanged, so the refusal refused the VEND and nothing else.
    described_b = ci.describe_identity(IdentityId=identity_b)
    assert described_b["IdentityId"] == identity_b, (
        f"DescribeIdentity must still resolve the refused identity {identity_b}, got "
        f"{described_b.get('IdentityId')!r}"
    )
    assert not described_b.get("Logins"), (
        f"the refused guest identity must still carry no logins, got "
        f"{described_b.get('Logins')!r}"
    )

    # ---- beats 5 and 6: restore by LOOSENING — add B's id — and the identical call succeeds.
    # Never tighten here: STS can serve a cached ALLOW for minutes after a trust-policy tightening.
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=_sub_scoped_trust_policy(pool_id, [identity_a, identity_b]),
    )
    creds_b = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_b),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=_TRUST_BUDGET_S,
        description="the loosened sub condition to admit identity B",
    )["Credentials"]
    arn_b = _client_from_credentials(ctx, "sts", creds_b).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in arn_b, (
        f"after adding B to the sub condition, B must assume {role_name}, got {arn_b}"
    )

    # And the grant is additive, not a swap: A still works, so the condition is a set membership
    # test rather than a single-value latch.
    recheck_a = ci.get_credentials_for_identity(IdentityId=identity_a)["Credentials"]
    recheck_arn = _client_from_credentials(
        ctx, "sts", recheck_a
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in recheck_arn, (
        f"identity A stopped working once B was added, so the sub condition is a latch rather "
        f"than a set: got {recheck_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
