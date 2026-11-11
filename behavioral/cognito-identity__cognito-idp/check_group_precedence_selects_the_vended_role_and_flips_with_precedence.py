"""group-precedence-selects-the-vended-role-and-flips-with-precedence."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "group-precedence-selects-the-vended-role-and-flips-with-precedence"
GROUP = "iam-trust"
SERVICES = ["cognito-identity", "cognito-idp"]

# Lower Precedence wins, so _FLIPPED (above the other group's value) hands the win over.
_PRECEDENCE_LOW = 1
_PRECEDENCE_HIGH = 10
_PRECEDENCE_FLIPPED = 20

_CLAIM_BUDGET_S = 120.0
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


def _decode_jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


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
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                },
            },
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust_policy,
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _set_roles(ci, pool_id, roles, role_mappings, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(
                IdentityPoolId=pool_id, Roles=roles, RoleMappings=role_mappings,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """A target client signed with the vended temporary credentials, passed by value only."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


@tags("axis:happy-path", "cap:c7", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The lower-Precedence group's role is the token's preferred_role and the vended role.

    Raising that group's Precedence above the other's flips both the claim and the vended session.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-prec-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName="sim2real-behav-prec-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    mapping_key = f"{provider}:{client_id}"

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_prec_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust = _cognito_trust_policy(pool_id)
    default_name, default_arn = _create_role(iam, ctx, trust, "prec-default")
    strong_name, strong_arn = _create_role(iam, ctx, trust, "prec-strong")
    weak_name, weak_arn = _create_role(iam, ctx, trust, "prec-weak")

    strong_group = ctx.unique_name("sim2real-behav-strong-")
    weak_group = ctx.unique_name("sim2real-behav-weak-")
    # CreateGroup validates the RoleArn, and a freshly created role is not immediately visible to
    # it — the retry waits for exactly that, and raises if the role never becomes usable.
    _poll_until(
        lambda: idp.create_group(
            GroupName=strong_group, UserPoolId=user_pool_id,
            RoleArn=strong_arn, Precedence=_PRECEDENCE_LOW,
        ),
        lambda r: r["Group"]["GroupName"] == strong_group,
        timeout_s=_TRUST_BUDGET_S,
        description="CreateGroup to accept the freshly created strong RoleArn",
    )
    ctx.on_cleanup(
        lambda: idp.delete_group(GroupName=strong_group, UserPoolId=user_pool_id)
    )
    _poll_until(
        lambda: idp.create_group(
            GroupName=weak_group, UserPoolId=user_pool_id,
            RoleArn=weak_arn, Precedence=_PRECEDENCE_HIGH,
        ),
        lambda r: r["Group"]["GroupName"] == weak_group,
        timeout_s=_TRUST_BUDGET_S,
        description="CreateGroup to accept the freshly created weak RoleArn",
    )
    ctx.on_cleanup(
        lambda: idp.delete_group(GroupName=weak_group, UserPoolId=user_pool_id)
    )

    username = ctx.unique_name("sim2real-behav-prec-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(
        UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username)
    )
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True,
    )
    for group in (weak_group, strong_group):
        idp.admin_add_user_to_group(
            UserPoolId=user_pool_id, Username=username, GroupName=group,
        )

    def _fresh_id_token():
        return idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]

    def _token_with_preferred_role(expected_arn, what):
        """Re-authenticate until the claim reflects *expected_arn*; raises if it never does."""
        holder = {}

        def _attempt():
            token = _fresh_id_token()
            holder["token"] = token
            holder["claims"] = _decode_jwt_claims(token)
            return holder["claims"]

        _poll_until(
            _attempt,
            lambda claims: claims.get("cognito:preferred_role") == expected_arn,
            timeout_s=_CLAIM_BUDGET_S,
            description=(
                f"a fresh ID token to carry cognito:preferred_role={expected_arn} ({what})"
            ),
        )
        claims = holder["claims"]
        assert set(claims.get("cognito:roles") or []) == {strong_arn, weak_arn}, (
            f"{what}: cognito:roles must list BOTH group roles regardless of precedence; expected "
            f"{sorted([strong_arn, weak_arn])}, got {sorted(claims.get('cognito:roles') or [])}"
        )
        return holder["token"], claims

    # The precedence rule is read off the minted token before any vend outcome is asserted.
    token_before, claims_before = _token_with_preferred_role(
        strong_arn, f"group at Precedence={_PRECEDENCE_LOW} outranks {_PRECEDENCE_HIGH}"
    )

    _set_roles(
        ci, pool_id, {"authenticated": default_arn},
        {mapping_key: {"Type": "Token", "AmbiguousRoleResolution": "Deny"}},
    )
    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)["RoleMappings"][mapping_key]
    assert stored["Type"] == "Token", (
        f"GetIdentityPoolRoles must echo a Token mapping, got {stored!r}"
    )

    logins_before = {provider: token_before}
    identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins_before)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    creds_before = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins=logins_before,
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=_TRUST_BUDGET_S,
        description="the Token mapping to vend the preferred group role",
    )["Credentials"]
    arn_before = _client_from_credentials(
        ctx, "sts", creds_before
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{strong_name}/" in arn_before, (
        f"the vended session must be the lower-precedence group's role {strong_name} — the token "
        f"said cognito:preferred_role={claims_before.get('cognito:preferred_role')!r} — got "
        f"{arn_before}"
    )
    assert f":assumed-role/{default_name}/" not in arn_before, (
        f"the Token mapping must not fall back to the pool's default authenticated role "
        f"{default_name} while a preferred role exists; got {arn_before}"
    )

    idp.update_group(
        GroupName=strong_group, UserPoolId=user_pool_id,
        Precedence=_PRECEDENCE_FLIPPED,
    )
    updated = idp.get_group(GroupName=strong_group, UserPoolId=user_pool_id)["Group"]
    assert updated["Precedence"] == _PRECEDENCE_FLIPPED, (
        f"UpdateGroup must set Precedence={_PRECEDENCE_FLIPPED}, GetGroup reports "
        f"{updated.get('Precedence')!r}"
    )

    # Claims are computed at authentication time, so an issued token must not change.
    assert _decode_jwt_claims(token_before).get("cognito:preferred_role") == strong_arn, (
        "an already-issued ID token must not change when a group's Precedence changes; the token "
        f"minted before the flip now decodes to "
        f"{_decode_jwt_claims(token_before).get('cognito:preferred_role')!r}"
    )

    token_after, claims_after = _token_with_preferred_role(
        weak_arn, f"strong group demoted to Precedence={_PRECEDENCE_FLIPPED}"
    )
    logins_after = {provider: token_after}
    same_identity = ci.get_id(IdentityPoolId=pool_id, Logins=logins_after)["IdentityId"]
    assert same_identity == identity_id, (
        f"the same user through the same provider must resolve to the same identity; expected "
        f"{identity_id}, got {same_identity}"
    )
    creds_after = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins=logins_after,
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=_TRUST_BUDGET_S,
        description="the Token mapping to vend the newly preferred group role",
    )["Credentials"]
    arn_after = _client_from_credentials(
        ctx, "sts", creds_after
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{weak_name}/" in arn_after, (
        f"after the precedence flip the vended session must be {weak_name} — the token said "
        f"cognito:preferred_role={claims_after.get('cognito:preferred_role')!r} — got {arn_after}"
    )
    assert f":assumed-role/{strong_name}/" not in arn_after, (
        f"the demoted group's role {strong_name} must no longer be vended; got {arn_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
