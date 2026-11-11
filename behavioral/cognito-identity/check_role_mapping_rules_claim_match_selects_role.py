"""role-mapping-rules-claim-match-selects-role."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-mapping-rules-claim-match-selects-role"
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
    """A Rules role mapping vends credentials for the rule's RoleARN when the token claim matches,
    and falls back to the pool's authenticated role when no rule matches."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    idp, user_pool_id, client_id = _create_user_pool(ctx, custom_attributes=["tier"])
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    mapping_key = f"{provider}:{client_id}"

    admin_token = _mint_id_token(
        idp, ctx, user_pool_id, client_id,
        attributes=[{"Name": "custom:tier", "Value": "admin"}],
    )
    basic_token = _mint_id_token(
        idp, ctx, user_pool_id, client_id,
        attributes=[{"Name": "custom:tier", "Value": "basic"}],
    )

    pool_id = _create_identity_pool(
        ci, ctx, allow_unauth=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
    )

    trust = _cognito_trust_policy(pool_id)
    unauth_name, unauth_arn = _create_role(iam, ctx, trust, "unauth")
    auth_name, auth_arn = _create_role(iam, ctx, trust, "auth")
    rule_name, rule_arn = _create_role(iam, ctx, trust, "tieradmin")

    role_mappings = {
        mapping_key: {
            "Type": "Rules",
            "AmbiguousRoleResolution": "AuthenticatedRole",
            "RulesConfiguration": {"Rules": [{
                "Claim": "custom:tier",
                "MatchType": "Equals",
                "Value": "admin",
                "RoleARN": rule_arn,
            }]},
        },
    }
    _set_roles(
        ci, pool_id,
        {"authenticated": auth_arn, "unauthenticated": unauth_arn},
        role_mappings=role_mappings,
    )

    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert mapping_key in stored.get("RoleMappings", {}), (
        f"GetIdentityPoolRoles lost the provider:clientId mapping key; "
        f"got {sorted(stored.get('RoleMappings', {}))}"
    )
    stored_rule = stored["RoleMappings"][mapping_key]["RulesConfiguration"]["Rules"][0]
    assert stored_rule["RoleARN"] == rule_arn, (
        f"stored rule RoleARN {stored_rule['RoleARN']} != {rule_arn}"
    )

    def _assumed_arn(id_token):
        identity_id = ci.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]
        creds = _poll_until(
            lambda: ci.get_credentials_for_identity(
                IdentityId=identity_id, Logins={provider: id_token},
            ),
            lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
            description="GetCredentialsForIdentity to vend credentials",
        )["Credentials"]
        assert creds["AccessKeyId"].startswith("ASIA"), (
            f"vended AccessKeyId {creds['AccessKeyId']} is not an ASIA session key"
        )
        sts = _client_from_credentials(ctx, "sts", creds)
        return identity_id, sts.get_caller_identity()["Arn"]

    admin_identity, admin_arn_seen = _assumed_arn(admin_token)
    assert f":assumed-role/{rule_name}/" in admin_arn_seen, (
        f"matching claim custom:tier=admin should assume the rule role {rule_name}, "
        f"got caller arn {admin_arn_seen}"
    )
    assert auth_name not in admin_arn_seen, (
        f"matching claim must not fall back to the pool authenticated role {auth_name}: "
        f"{admin_arn_seen}"
    )

    basic_identity, basic_arn_seen = _assumed_arn(basic_token)
    assert basic_identity != admin_identity, (
        f"two distinct federated users shared identity {basic_identity}"
    )
    assert f":assumed-role/{auth_name}/" in basic_arn_seen, (
        f"non-matching claim must fall back to the authenticated role {auth_name} under "
        f"AmbiguousRoleResolution=AuthenticatedRole, got {basic_arn_seen}"
    )
    assert rule_name not in basic_arn_seen, (
        f"non-matching claim leaked the rule role {rule_name}: {basic_arn_seen}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
