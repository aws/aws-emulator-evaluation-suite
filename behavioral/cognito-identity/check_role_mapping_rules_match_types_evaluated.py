"""role-mapping-rules-match-types-evaluated."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-mapping-rules-match-types-evaluated"
GROUP = 'roles'
SERVICES = ['cognito-identity']



def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
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


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _cognito_trust_policy(pool_id, amr=None):
    condition = {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}}
    if amr:
        condition["ForAnyValue:StringLike"] = {"cognito-identity.amazonaws.com:amr": amr}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": condition,
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _set_roles(ci, pool_id, roles, role_mappings=None, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    kwargs = {"IdentityPoolId": pool_id, "Roles": roles}
    if role_mappings is not None:
        kwargs["RoleMappings"] = role_mappings
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """A client for ``service`` on the same target, signed with the vended temporary credentials.

    The credentials are passed by value and never written into os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _create_user_pool(ctx, custom_attributes=()):
    """A real user pool + app client; Cognito rejects fabricated third-party tokens."""
    idp = ctx.client("cognito-idp")
    kwargs = {
        "PoolName": ctx.unique_name("sim2real-behav-up-"),
        "UserPoolTags": {"sim2real": CHECK},
    }
    if custom_attributes:
        kwargs["Schema"] = [{
            "Name": attr,
            "AttributeDataType": "String",
            "Mutable": True,
            "Required": False,
            "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "256"},
        } for attr in custom_attributes]
    pool_id = idp.create_user_pool(**kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="sim2real-behav-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return idp, pool_id, client_id


def _mint_id_token(idp, ctx, pool_id, client_id, attributes=(), groups=()):
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=list(attributes),
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )
    for group in groups:
        idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]



@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each Rules MatchType (Contains, StartsWith, NotEqual), applied as a single-rule mapping, is
    evaluated with its own semantics: the matching login gets the rule role, the other falls back."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    idp, user_pool_id, client_id = _create_user_pool(ctx, custom_attributes=["team"])
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    mapping_key = f"{provider}:{client_id}"

    pool_id = _create_identity_pool(
        ci, ctx, allow_unauth=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
    )

    trust = _cognito_trust_policy(pool_id)
    _, unauth_arn = _create_role(iam, ctx, trust, "unauth")
    auth_name, auth_arn = _create_role(iam, ctx, trust, "auth")
    rule_name, rule_arn = _create_role(iam, ctx, trust, "matched")

    def _fresh_identity(team):
        """A new user, token and IdentityId for one claim value; returns (identity_id, token).

        Per case because the vended session is cached per IdentityId and get_id is idempotent per
        login, so a reused identity would satisfy later cases with the first case's credentials."""
        token = _mint_id_token(
            idp, ctx, user_pool_id, client_id,
            attributes=[{"Name": "custom:team", "Value": team}],
        )
        identity_id = ci.get_id(
            IdentityPoolId=pool_id, Logins={provider: token},
        )["IdentityId"]
        return identity_id, token

    def _caller_arn(identity_id, token):
        creds = ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins={provider: token},
        )["Credentials"]
        return _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]

    # (MatchType, Value) triples where "team-alpha-eng" matches and "beta" does not.
    cases = [
        ("Contains", "alpha"),
        ("StartsWith", "team-"),
        ("NotEqual", "beta"),
    ]
    for match_type, value in cases:
        _set_roles(
            ci, pool_id,
            {"authenticated": auth_arn, "unauthenticated": unauth_arn},
            role_mappings={mapping_key: {
                "Type": "Rules",
                "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": {"Rules": [{
                    "Claim": "custom:team",
                    "MatchType": match_type,
                    "Value": value,
                    "RoleARN": rule_arn,
                }]},
            }},
        )
        stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
        stored_rule = stored["RoleMappings"][mapping_key]["RulesConfiguration"]["Rules"][0]
        assert stored_rule["MatchType"] == match_type, (
            f"GetIdentityPoolRoles returned MatchType {stored_rule['MatchType']!r}, "
            f"expected {match_type!r}"
        )

        match_identity, match_token = _fresh_identity("team-alpha-eng")
        other_identity, other_token = _fresh_identity("beta")

        matched_arn = _poll_until(
            lambda: _caller_arn(match_identity, match_token),
            lambda a: f":assumed-role/{rule_name}/" in a,
            timeout_s=180.0,
            description=f"MatchType={match_type} to select the rule role for 'team-alpha-eng'",
        )
        assert auth_name not in matched_arn, (
            f"MatchType={match_type} value={value!r}: matching claim must not fall back to "
            f"{auth_name}, got {matched_arn}"
        )

        unmatched_arn = _poll_until(
            lambda: _caller_arn(other_identity, other_token),
            lambda a: f":assumed-role/{auth_name}/" in a,
            timeout_s=180.0,
            description=f"MatchType={match_type} to fall back for the claim 'beta'",
        )
        assert rule_name not in unmatched_arn, (
            f"MatchType={match_type} value={value!r}: claim 'beta' must NOT match, but the "
            f"rule role {rule_name} was vended: {unmatched_arn}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
