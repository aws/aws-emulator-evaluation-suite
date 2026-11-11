"""role-mapping-token-type-uses-preferred-role."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-mapping-token-type-uses-preferred-role"
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


def _decode_jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
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
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
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
    """A client on the target signed with the vended temporary credentials."""
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
    kwargs = {"PoolName": ctx.unique_name("sim2real-behav-up-")}
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



@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Token role mapping vends credentials for the group role named by cognito:preferred_role
    in the ID token; under AmbiguousRoleResolution=Deny a token without cognito:roles gets none."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    idp, user_pool_id, client_id = _create_user_pool(ctx)
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
    group_role_name, group_role_arn = _create_role(iam, ctx, trust, "grouprole")

    group_name = ctx.unique_name("sim2real-behav-grp-")
    _poll_until(
        lambda: idp.create_group(
            GroupName=group_name,
            UserPoolId=user_pool_id,
            RoleArn=group_role_arn,
            Precedence=0,
        ),
        lambda r: r["Group"]["GroupName"] == group_name,
        timeout_s=180.0,
        description="CreateGroup to accept the freshly created RoleArn",
    )
    ctx.on_cleanup(lambda: idp.delete_group(GroupName=group_name, UserPoolId=user_pool_id))

    grouped_token = _mint_id_token(
        idp, ctx, user_pool_id, client_id, groups=[group_name],
    )
    ungrouped_token = _mint_id_token(idp, ctx, user_pool_id, client_id)

    grouped_claims = _decode_jwt_claims(grouped_token)
    assert grouped_claims.get("cognito:preferred_role") == group_role_arn, (
        f"ID token for a group member must carry cognito:preferred_role={group_role_arn}, got "
        f"{grouped_claims.get('cognito:preferred_role')!r}"
    )
    assert group_role_arn in grouped_claims.get("cognito:roles", []), (
        f"cognito:roles must list the group role, got {grouped_claims.get('cognito:roles')!r}"
    )
    ungrouped_claims = _decode_jwt_claims(ungrouped_token)
    assert "cognito:preferred_role" not in ungrouped_claims, (
        "a user in no group must not receive cognito:preferred_role, got "
        f"{ungrouped_claims.get('cognito:preferred_role')!r}"
    )

    _set_roles(
        ci, pool_id,
        {"authenticated": auth_arn, "unauthenticated": unauth_arn},
        role_mappings={mapping_key: {"Type": "Token", "AmbiguousRoleResolution": "Deny"}},
    )
    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)["RoleMappings"][mapping_key]
    assert stored["Type"] == "Token" and stored["AmbiguousRoleResolution"] == "Deny", (
        f"GetIdentityPoolRoles must echo the Token mapping verbatim, got {stored!r}"
    )
    assert "RulesConfiguration" not in stored, (
        f"a Token mapping must not gain a RulesConfiguration: {stored!r}"
    )

    grouped_identity = ci.get_id(
        IdentityPoolId=pool_id, Logins={provider: grouped_token},
    )["IdentityId"]
    creds = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=grouped_identity, Logins={provider: grouped_token},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        description="the group member to be vended credentials",
    )["Credentials"]
    caller_arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{group_role_name}/" in caller_arn, (
        f"Token mapping must assume the cognito:preferred_role {group_role_name}, got {caller_arn}"
    )
    assert auth_name not in caller_arn, (
        f"Token mapping must not fall back to the pool authenticated role {auth_name}: {caller_arn}"
    )

    ungrouped_identity = ci.get_id(
        IdentityPoolId=pool_id, Logins={provider: ungrouped_token},
    )["IdentityId"]
    try:
        response = ci.get_credentials_for_identity(
            IdentityId=ungrouped_identity, Logins={provider: ungrouped_token},
        )
    except ClientError as exc:
        denied = exc.response.get("Error", {})
    else:
        raise AssertionError(
            "a token without cognito:roles must not resolve under Token/Deny, but "
            f"GetCredentialsForIdentity vended {response.get('Credentials', {}).get('AccessKeyId')!r}"
        )
    assert denied.get("Code") == "NotAuthorizedException", (
        f"expected NotAuthorizedException for a token with no cognito:roles claim, got {denied!r}"
    )
    assert denied.get("Message") == (
        f"The ambiguous role mapping rules for: {provider} denied this request."
    ), (
        f"expected the exact refusal message AWS returns, got {denied.get('Message')!r}"
    )

    # The denial must be scoped to the claim-less login, not to the pool.
    recheck = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=grouped_identity, Logins={provider: grouped_token},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=60.0,
        description="the group member to be vended credentials again",
    )
    assert recheck["Credentials"]["AccessKeyId"].startswith("ASIA"), (
        f"the group member stopped working after the ungrouped login's denial: {recheck!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
