"""basic-flow-get-open-id-token-refused-while-role-mappings-are-configured."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "basic-flow-get-open-id-token-refused-while-role-mappings-are-configured"
GROUP = "identity-flow"
SERVICES = ["cognito-identity"]

_REFUSAL_MESSAGE = "Basic (classic) flow is not supported with RoleMappings, please use enhanced flow."
_REFUSAL_CODE = "InvalidParameterException"

_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
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
    """With a RoleMappings entry set, GetOpenIdToken (basic flow) is refused while the enhanced flow
    vends the mapped role; clearing the mappings makes the same call succeed and redeem at STS.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    # A real user pool: the identity pool rejects fabricated third-party tokens.
    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-classic-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName="sim2real-behav-classic-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    mapping_key = f"{provider}:{client_id}"

    username = ctx.unique_name("sim2real-behav-classic-user-")
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
    id_token = idp.admin_initiate_auth(
        UserPoolId=user_pool_id, ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]
    logins = {provider: id_token}

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_classic_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        AllowClassicFlow=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust = _cognito_trust_policy(pool_id)
    auth_name, auth_arn = _create_role(iam, ctx, trust, "classic-auth")
    mapped_name, mapped_arn = _create_role(iam, ctx, trust, "classic-mapped")
    _set_roles(ci, pool_id, {"authenticated": auth_arn}, {})

    identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    def _redeem_basic_flow(what):
        """GetOpenIdToken then AssumeRoleWithWebIdentity; assert at STS, not at Cognito."""
        token = _poll_until(
            lambda: ci.get_open_id_token(IdentityId=identity_id, Logins=logins),
            lambda r: bool(r.get("Token")),
            timeout_s=120.0,
            description=f"GetOpenIdToken to mint a token ({what})",
        )["Token"]
        assumed = _poll_until(
            lambda: sts.assume_role_with_web_identity(
                RoleArn=auth_arn,
                RoleSessionName="sim2real-basic-flow",
                WebIdentityToken=token,
            ),
            lambda r: "Credentials" in r,
            timeout_s=180.0,
            description=f"the freshly created role to accept the OIDC token ({what})",
        )
        assert assumed["SubjectFromWebIdentityToken"] == identity_id, (
            f"{what}: STS must report the identity id as the token subject, expected "
            f"{identity_id}, got {assumed.get('SubjectFromWebIdentityToken')!r}"
        )
        assert assumed["Audience"] == pool_id, (
            f"{what}: STS must report the pool id as the audience, expected {pool_id}, got "
            f"{assumed.get('Audience')!r}"
        )
        caller = _client_from_credentials(
            ctx, "sts", assumed["Credentials"]
        ).get_caller_identity()
        assert f":assumed-role/{auth_name}/" in caller["Arn"], (
            f"{what}: the redeemed session must be {auth_name}, got {caller['Arn']}"
        )

    # Positive control: the basic flow redeems at STS while no mappings exist.
    _redeem_basic_flow("no role mappings configured")

    _set_roles(
        ci, pool_id, {"authenticated": auth_arn},
        {mapping_key: {
            "Type": "Rules",
            "AmbiguousRoleResolution": "AuthenticatedRole",
            "RulesConfiguration": {"Rules": [{
                "Claim": "cognito:username",
                "MatchType": "Equals",
                "Value": username,
                "RoleARN": mapped_arn,
            }]},
        }},
    )
    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert mapping_key in stored.get("RoleMappings", {}), (
        f"GetIdentityPoolRoles must report the mapping just set under {mapping_key!r}, got "
        f"{sorted(stored.get('RoleMappings', {}))}"
    )

    try:
        minted = ci.get_open_id_token(IdentityId=identity_id, Logins=logins)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        message = err.get("Message") or ""
    else:
        raise AssertionError(
            "GetOpenIdToken must be refused on a pool that has RoleMappings — the basic flow lets "
            "the client pick its own role and would bypass the mapping entirely — but it returned "
            f"a token of {len(minted.get('Token') or '')} chars for identity "
            f"{minted.get('IdentityId')!r}"
        )
    assert code == _REFUSAL_CODE, (
        f"expected {_REFUSAL_CODE} for a basic-flow request against a pool with "
        f"RoleMappings, got {code!r}: {message!r}"
    )
    assert message == _REFUSAL_MESSAGE, (
        f"expected message {_REFUSAL_MESSAGE!r}, got {message!r}"
    )

    # The enhanced flow still vends, as the mapped role rather than the default authenticated one.
    enhanced = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=180.0,
        description="the enhanced flow to keep vending while the basic flow is refused",
    )["Credentials"]
    enhanced_arn = _client_from_credentials(
        ctx, "sts", enhanced
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{mapped_name}/" in enhanced_arn, (
        f"with the mapping in place the enhanced flow must vend the MAPPED role {mapped_name} "
        f"(that is what the basic flow was refused for bypassing), got {enhanced_arn}"
    )

    # SetIdentityPoolRoles replaces the mappings, so RoleMappings={} clears them.
    _set_roles(ci, pool_id, {"authenticated": auth_arn}, {})
    cleared = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert not cleared.get("RoleMappings"), (
        f"SetIdentityPoolRoles with RoleMappings={{}} must clear them; GetIdentityPoolRoles still "
        f"reports {cleared.get('RoleMappings')!r}"
    )
    _redeem_basic_flow("role mappings cleared again")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
