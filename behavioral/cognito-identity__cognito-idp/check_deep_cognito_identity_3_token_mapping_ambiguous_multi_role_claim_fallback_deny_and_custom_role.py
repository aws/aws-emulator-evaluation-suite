"""deep-cognito-identity-3-token-mapping-ambiguous-multi-role-claim-fallback-deny-and-custom-role."""
from __future__ import annotations

import base64
import json
import time
import uuid
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-3-token-mapping-ambiguous-multi-role-claim-fallback-deny-and-custom-role"
GROUP = "role-mapping"
SERVICES = ["cognito-identity", "cognito-idp"]

#: Both groups sit at the SAME precedence. With distinct role ARNs, that tie is what leaves the
#: token with several cognito:roles and no cognito:preferred_role, the ambiguity under test.
_TIED_PRECEDENCE = 5

#: Group configuration reaches token minting asynchronously, so every claim wait re-authenticates.
_CLAIM_BUDGET_S = 120.0
#: A freshly created role's trust policy is not usable by STS straight away. This is the bounded
#: retry at FIRST USE of the trust, as opposed to a sleep standing in for it.
_TRUST_BUDGET_S = 240.0
#: How long a SetIdentityPoolRoles change may take to reach GetCredentialsForIdentity.
_MAPPING_BUDGET_S = 60.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=4.0, description="condition"):
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


def _refusal(fn, what, timeout_s=_MAPPING_BUDGET_S, interval_s=3.0):
    """Call fn() until it raises a ClientError and return that error's (code, message).

    A SUCCESS is never mistaken for a code. Within the window it is treated as a mapping change
    that has not landed yet. If the call is still succeeding when the window closes, this raises
    and names the role that was vended, because a target that keeps handing out credentials where
    real AWS refuses is the strongest failure the check can report.
    """
    deadline = time.time() + timeout_s
    vended = None
    while True:
        try:
            vended = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.time() >= deadline:
            raise AssertionError(
                f"{what}: expected a refusal, but GetCredentialsForIdentity kept SUCCEEDING for "
                f"{timeout_s}s and vended AccessKeyId "
                f"{vended.get('Credentials', {}).get('AccessKeyId')!r}"
            )
        time.sleep(interval_s)


def _decode_jwt(token):
    """Split and decode a compact JWS. Returns (header, claims); asserts the structure."""
    parts = token.split(".")
    assert len(parts) == 3, f"the IdToken is not a three-part compact JWS: {token[:24]!r}..."

    def _seg(seg):
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

    return _seg(parts[0]), _seg(parts[1])


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
    name = ctx.unique_name(f"sim2real-xsvc-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust_policy,
        Description="sim2real cross-service probe role for Cognito Identity token mapping",
        Tags=[{"Key": "sim2real", "Value": "deep-cognito-identity-3"}],
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


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An ambiguous Token mapping (several cognito:roles, no preferred_role) vends the pool default
    under AuthenticatedRole and refuses under Deny; under Deny a CustomRoleArn in cognito:roles is
    honoured and one outside it is refused with NotAuthorizedException.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    # ---- user pool and app client (cognito-idp side of the boundary)
    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-tokamb-up-"),
        UserPoolTags={"sim2real": "deep-cognito-identity-3"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName="sim2real-xsvc-tokamb-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: idp.delete_user_pool_client(UserPoolId=user_pool_id, ClientId=client_id)
    )
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    mapping_key = f"{provider}:{client_id}"

    # ---- identity pool (cognito-identity side of the boundary)
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_xsvc_tokamb_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": "deep-cognito-identity-3"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # Four roles with IDENTICAL trust: the pool default, one per group, and one outside every
    # group. Any one of them is assumable by this pool's authenticated identities, so whatever
    # separates them below is the role mapping, never IAM.
    trust = _cognito_trust_policy(pool_id)
    default_name, default_arn = _create_role(iam, ctx, trust, "tokamb-default")
    a_name, a_arn = _create_role(iam, ctx, trust, "tokamb-ga")
    b_name, b_arn = _create_role(iam, ctx, trust, "tokamb-gb")
    outside_name, outside_arn = _create_role(iam, ctx, trust, "tokamb-outside")
    assert len({default_arn, a_arn, b_arn, outside_arn}) == 4, (
        f"the four roles must be distinct, got {[default_arn, a_arn, b_arn, outside_arn]!r}"
    )

    group_a = ctx.unique_name("sim2real-xsvc-tokamb-ga-")
    group_b = ctx.unique_name("sim2real-xsvc-tokamb-gb-")
    for group, role_arn in ((group_a, a_arn), (group_b, b_arn)):
        # CreateGroup validates the RoleArn, and a freshly created role is not immediately visible
        # to it. The retry waits for exactly that and raises if the role never becomes usable.
        _poll_until(
            lambda g=group, r=role_arn: idp.create_group(
                GroupName=g, UserPoolId=user_pool_id, RoleArn=r, Precedence=_TIED_PRECEDENCE,
            ),
            lambda resp, g=group: resp["Group"]["GroupName"] == g,
            timeout_s=_TRUST_BUDGET_S,
            description=f"CreateGroup {group} to accept the freshly created RoleArn {role_arn}",
        )
        ctx.on_cleanup(
            lambda g=group: idp.delete_group(GroupName=g, UserPoolId=user_pool_id)
        )

    # The authoritative group configuration. The token's claims are checked against it below.
    configured = {}
    for group in (group_a, group_b):
        g = idp.get_group(GroupName=group, UserPoolId=user_pool_id)["Group"]
        assert g.get("Precedence") == _TIED_PRECEDENCE, (
            f"GetGroup {group} must report Precedence={_TIED_PRECEDENCE}, got "
            f"{g.get('Precedence')!r}"
        )
        configured[group] = g.get("RoleArn")
    assert configured == {group_a: a_arn, group_b: b_arn}, (
        f"GetGroup must report each group's RoleArn as created; got {configured!r}"
    )

    username = ctx.unique_name("sim2real-xsvc-tokamb-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True,
    )
    for group in (group_a, group_b):
        idp.admin_add_user_to_group(UserPoolId=user_pool_id, Username=username, GroupName=group)
    member_of = {
        g["GroupName"]
        for g in idp.admin_list_groups_for_user(
            UserPoolId=user_pool_id, Username=username,
        )["Groups"]
    }
    assert member_of == {group_a, group_b}, (
        f"the user must be in exactly both groups, AdminListGroupsForUser says {sorted(member_of)}"
    )

    # Read the ambiguity off the target's own ID token before predicting any vend outcome.
    both = {a_arn, b_arn}
    holder = {}

    def _sign_in():
        token = idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]
        holder["token"] = token
        holder["header"], holder["claims"] = _decode_jwt(token)
        return holder["claims"]

    _poll_until(
        _sign_in,
        lambda claims: set(claims.get("cognito:roles") or []) == both,
        timeout_s=_CLAIM_BUDGET_S,
        description=f"a fresh ID token whose cognito:roles names both group roles {sorted(both)}",
    )
    id_token, header, claims = holder["token"], holder["header"], holder["claims"]

    # The decode is checked against the identity it should describe, so a mis-decoded token, or
    # one minted for a different pool, client or user, cannot pass as evidence.
    assert header.get("alg") == "RS256" and header.get("kid"), (
        f"the ID token header must be an RS256 JWS with a kid, got {header!r}"
    )
    assert claims.get("token_use") == "id", (
        f"expected token_use='id', got {claims.get('token_use')!r}"
    )
    # The issuer is https://cognito-idp.<region>.<domain>/<user pool id>; the domain is the
    # target's own, so the service label, region and pool id are matched by position.
    iss = claims.get("iss")
    iss_parts = urlsplit(iss) if isinstance(iss, str) else None
    iss_labels = (iss_parts.hostname or "").split(".") if iss_parts else []
    assert (iss_parts is not None and iss_parts.scheme == "https"
            and iss_labels[:2] == ["cognito-idp", ctx.region] and len(iss_labels) > 2
            and all(iss_labels[2:]) and iss_parts.path == f"/{user_pool_id}"
            and not iss_parts.query and not iss_parts.fragment), (
        f"the ID token must be issued by https://cognito-idp.{ctx.region}.<domain>/{user_pool_id}, "
        f"got iss={iss!r}"
    )
    assert claims.get("aud") == client_id, (
        f"the ID token audience must be the app client {client_id}, got {claims.get('aud')!r}"
    )
    assert claims.get("cognito:username") == username, (
        f"the ID token must describe {username}, got {claims.get('cognito:username')!r}"
    )
    assert set(claims.get("cognito:groups") or []) == {group_a, group_b}, (
        f"cognito:groups must list both groups, got {claims.get('cognito:groups')!r}"
    )
    roles_claim = claims.get("cognito:roles") or []
    assert sorted(roles_claim) == sorted(configured.values()), (
        f"cognito:roles must equal GetGroup's RoleArns {sorted(configured.values())}, got "
        f"{roles_claim!r}"
    )
    assert "cognito:preferred_role" not in claims, (
        f"two groups tied at Precedence={_TIED_PRECEDENCE} with distinct roles must leave "
        f"cognito:preferred_role ABSENT, but the token carries "
        f"{claims.get('cognito:preferred_role')!r}"
    )
    assert default_arn not in roles_claim and outside_arn not in roles_claim, (
        f"neither the pool default nor the outside role may appear in cognito:roles: {roles_claim!r}"
    )

    logins = {provider: id_token}
    deny_message = f"The ambiguous role mapping rules for: {provider} denied this request."

    def _not_in_claim(role_arn):
        return f"CustomRoleARN: {role_arn} is not present in the token in the cognito:roles claim"

    def _vend(**extra):
        return ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins, **extra)

    def _vended_arn(resp):
        return _client_from_credentials(
            ctx, "sts", resp["Credentials"]
        ).get_caller_identity()["Arn"]

    # ---- Arm A (control): Token + AuthenticatedRole falls back to the pool default.
    _set_roles(
        ci, pool_id, {"authenticated": default_arn},
        {mapping_key: {"Type": "Token", "AmbiguousRoleResolution": "AuthenticatedRole"}},
    )
    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert stored["RoleMappings"].get(mapping_key) == {
        "Type": "Token", "AmbiguousRoleResolution": "AuthenticatedRole",
    }, f"GetIdentityPoolRoles must echo the Token/AuthenticatedRole mapping, got {stored!r}"
    assert stored["Roles"] == {"authenticated": default_arn}, (
        f"GetIdentityPoolRoles must echo the pool default role, got {stored['Roles']!r}"
    )

    identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    fallback = _poll_until(
        lambda: _vend(),
        lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
        timeout_s=_TRUST_BUDGET_S,
        description="Token/AuthenticatedRole to vend the pool default role for the ambiguous token",
    )
    assert fallback["IdentityId"] == identity_id, (
        f"credentials must be vended for {identity_id}, got {fallback['IdentityId']!r}"
    )
    fallback_arn = _vended_arn(fallback)
    assert f":assumed-role/{default_name}/" in fallback_arn, (
        f"Arm A: an ambiguous Token mapping under AuthenticatedRole must vend the pool default "
        f"role {default_name}, got {fallback_arn}"
    )
    for name in (a_name, b_name):
        assert f":assumed-role/{name}/" not in fallback_arn, (
            f"Arm A: with no cognito:preferred_role the fallback must NOT pick a group role, "
            f"yet it vended {name}: {fallback_arn}"
        )

    # ---- Arm B: change ONE thing, the resolution, to Deny. Same identity, same token.
    _set_roles(
        ci, pool_id, {"authenticated": default_arn},
        {mapping_key: {"Type": "Token", "AmbiguousRoleResolution": "Deny"}},
    )
    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)["RoleMappings"].get(mapping_key)
    assert stored == {"Type": "Token", "AmbiguousRoleResolution": "Deny"}, (
        f"GetIdentityPoolRoles must echo the Token/Deny mapping, got {stored!r}"
    )
    code, message = _refusal(
        lambda: _vend(), "Arm B: Token/Deny on a multi-role token with no preferred role",
    )
    assert code == "NotAuthorizedException", (
        f"Arm B: an ambiguous Token mapping under Deny must be refused with "
        f"NotAuthorizedException, got {code!r} ({message!r})"
    )
    assert message == deny_message, (
        f"Arm B: the Deny refusal must carry AWS's exact message {deny_message!r}, got {message!r}"
    )

    # ---- Arm C: still Deny. A CustomRoleArn present in cognito:roles is HONOURED. Both roles are
    # tried, so a target that only ever vends the first claim element fails on the second.
    for name, arn in ((a_name, a_arn), (b_name, b_arn)):
        honoured = _poll_until(
            lambda r=arn: _vend(CustomRoleArn=r),
            lambda resp: bool(resp.get("Credentials", {}).get("SessionToken")),
            timeout_s=_TRUST_BUDGET_S,
            description=f"Token/Deny to honour CustomRoleArn={arn} present in cognito:roles",
        )
        honoured_arn = _vended_arn(honoured)
        assert f":assumed-role/{name}/" in honoured_arn, (
            f"Arm C: CustomRoleArn={arn} is in cognito:roles and must be vended under Deny, "
            f"but the session is {honoured_arn}"
        )
        assert f":assumed-role/{default_name}/" not in honoured_arn, (
            f"Arm C: an honoured CustomRoleArn must not degrade to the pool default: {honoured_arn}"
        )

    # A CustomRoleArn OUTSIDE cognito:roles is refused. The outside role's trust is identical to
    # the group roles', so only claim membership can be what refuses it.
    code, message = _refusal(
        lambda: _vend(CustomRoleArn=outside_arn),
        f"Arm C: CustomRoleArn={outside_arn} absent from cognito:roles",
    )
    assert code == "NotAuthorizedException", (
        f"Arm C: a CustomRoleArn absent from cognito:roles must be refused with "
        f"NotAuthorizedException, got {code!r} ({message!r})"
    )
    assert message == _not_in_claim(outside_arn), (
        f"Arm C: the refusal must carry AWS's exact message {_not_in_claim(outside_arn)!r}, "
        f"got {message!r}"
    )
    # The same holds for the pool default role. Arm A vended it through the fallback, but it is not
    # in cognito:roles, so the fallback cannot be reached by naming it.
    code, message = _refusal(
        lambda: _vend(CustomRoleArn=default_arn),
        f"Arm C: CustomRoleArn={default_arn} (pool default, absent from cognito:roles)",
    )
    assert code == "NotAuthorizedException", (
        f"Arm C: naming the pool default as CustomRoleArn must be refused with "
        f"NotAuthorizedException, got {code!r} ({message!r})"
    )
    assert message == _not_in_claim(default_arn), (
        f"Arm C: the refusal must carry AWS's exact message {_not_in_claim(default_arn)!r}, "
        f"got {message!r}"
    )

    # The refusals left no state behind. The bare call is still denied, and an in-claim
    # CustomRoleArn still vends, so each refusal was scoped to its own request.
    code, message = _refusal(lambda: _vend(), "Arm B recheck after the Arm C probes")
    assert code == "NotAuthorizedException", (
        f"after the CustomRoleArn probes the bare call must still be NotAuthorizedException, got "
        f"{code!r} ({message!r})"
    )
    assert message == deny_message, (
        f"the recheck refusal must carry AWS's exact message {deny_message!r}, got {message!r}"
    )
    recheck_arn = _vended_arn(_vend(CustomRoleArn=a_arn))
    assert f":assumed-role/{a_name}/" in recheck_arn, (
        f"after the rejected CustomRoleArns, the in-claim role {a_name} must still be vended; "
        f"got {recheck_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
