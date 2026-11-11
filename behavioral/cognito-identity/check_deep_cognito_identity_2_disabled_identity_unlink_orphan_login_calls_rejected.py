"""deep-cognito-identity-2-disabled-identity-unlink-orphan-login-calls-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-2-disabled-identity-unlink-orphan-login-calls-rejected"
GROUP = 'identity-lifecycle'
SERVICES = ['cognito-identity']

COGNITO_LOGIN = "cognito-identity.amazonaws.com"
DISABLED = "DISABLED"
ERR_NOT_AUTHORIZED = "NotAuthorizedException"
MSG_LOGINS_DONT_MATCH = (
    "Logins don't match. Please include at least one valid login for this identity or identity pool."
)
# Retryable only while the authenticated role assignment propagates to the credential path.
ERR_POOL_CONFIG = "InvalidIdentityPoolConfigurationException"
CREDENTIALS_SESSION = "CognitoIdentityCredentials"


def _err(fn):
    """Call fn(); return (Code, Message) of its ClientError, and fail the check if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _retry_on(fn, codes, timeout_s=180.0, interval_s=3.0, description="call"):
    """Retry fn() while it raises one of `codes` (propagation), up to a bounded deadline."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.time() >= deadline:
                raise AssertionError(f"{description} did not succeed: {code!r} {exc}") from exc
        time.sleep(interval_s)


def _list_identities(ci, pool_id):
    out, token = {}, None
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        page = ci.list_identities(**kwargs)
        out.update({i["IdentityId"]: i.get("Logins") for i in page.get("Identities", [])})
        token = page.get("NextToken")
        if not token:
            return out


def _create_user_pool(ctx):
    """A real user pool + app client: Cognito validates provider tokens, so a fabricated one is
    refused and cannot stand in for a federated login."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-unlink-orphan-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="sim2real-unlink-orphan",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return idp, pool_id, client_id


def _mint_id_token(idp, ctx, pool_id, client_id):
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """After UnlinkIdentity leaves Logins ["DISABLED"], GetOpenIdToken/GetCredentialsForIdentity with
    the removed login fail NotAuthorizedException "Logins don't match", while a sibling still works,
    no identity is minted, and tokens/sessions issued before the unlink stay valid.

    Reference: https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_UnlinkIdentity.html
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    idp, user_pool_id, client_id = _create_user_pool(ctx)
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    token_orphan = _mint_id_token(idp, ctx, user_pool_id, client_id)
    token_sibling = _mint_id_token(idp, ctx, user_pool_id, client_id)

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_unlink_orphan_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        AllowClassicFlow=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider, "ClientId": client_id, "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO_LOGIN},
            "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    })
    role_name = ctx.unique_name("sim2real-unlink-orphan-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    partition = role_arn.split(":")[1]
    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})

    def _assumed_arn(session):
        return f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{session}"

    def _caller_arn(access_key, secret, session_token):
        return ctx.client("sts", creds={
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret,
            "aws_session_token": session_token,
        }).get_caller_identity()["Arn"]

    orphan_id = ci.get_id(IdentityPoolId=pool_id, Logins={provider: token_orphan})["IdentityId"]
    sibling_id = ci.get_id(IdentityPoolId=pool_id, Logins={provider: token_sibling})["IdentityId"]
    assert orphan_id != sibling_id, f"two users must get two identities, both got {orphan_id!r}"

    # --- positive control BEFORE: the calls under test succeed on the identity-to-be-orphaned ---
    assert ci.describe_identity(IdentityId=orphan_id).get("Logins") == [provider], (
        "pre-unlink identity must list exactly the user-pool provider"
    )
    pre_vend = _retry_on(
        lambda: ci.get_credentials_for_identity(IdentityId=orphan_id, Logins={provider: token_orphan}),
        {ERR_POOL_CONFIG}, description="pre-unlink GetCredentialsForIdentity",
    )
    assert pre_vend["IdentityId"] == orphan_id, (
        f"pre-unlink credentials were vended for {pre_vend['IdentityId']!r}, not {orphan_id!r}"
    )
    pre_open = ci.get_open_id_token(IdentityId=orphan_id, Logins={provider: token_orphan})
    assert pre_open["IdentityId"] == orphan_id, (
        f"pre-unlink GetOpenIdToken answered for {pre_open['IdentityId']!r}, not {orphan_id!r}"
    )
    pre_openid_token = pre_open["Token"]
    pre_session_name = "sim2real-pre-unlink"
    pre_session = _retry_on(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=role_arn, RoleSessionName=pre_session_name, WebIdentityToken=pre_openid_token),
        {"AccessDenied"}, description="pre-unlink AssumeRoleWithWebIdentity",
    )["Credentials"]
    arn = _caller_arn(pre_session["AccessKeyId"], pre_session["SecretAccessKey"],
                      pre_session["SessionToken"])
    assert arn == _assumed_arn(pre_session_name), (
        f"the pre-unlink STS session must authenticate as {_assumed_arn(pre_session_name)!r}, got {arn!r}"
    )

    # --- the transition: unlink the only login ------------------------------------------------
    # The login is deliberately never re-resolved through GetId afterwards: that maps it to a NEW
    # identity, and the calls below would be re-routed there rather than refused.
    ci.unlink_identity(IdentityId=orphan_id, Logins={provider: token_orphan}, LoginsToRemove=[provider])

    described = ci.describe_identity(IdentityId=orphan_id)
    assert described["IdentityId"] == orphan_id and described.get("Logins") == [DISABLED], (
        f"DescribeIdentity on the orphan must SUCCEED with Logins exactly [{DISABLED!r}], got "
        f"{described!r}"
    )

    # --- the degradation: the same two calls, same login, are now refused ---------------------
    for op, call in (
        ("GetOpenIdToken",
         lambda: ci.get_open_id_token(IdentityId=orphan_id, Logins={provider: token_orphan})),
        ("GetCredentialsForIdentity",
         lambda: ci.get_credentials_for_identity(IdentityId=orphan_id, Logins={provider: token_orphan})),
    ):
        code, msg = _err(call)
        assert code == ERR_NOT_AUTHORIZED, (
            f"{op} on the orphan with its former login must be {ERR_NOT_AUTHORIZED}, got {code!r} "
            f"({msg!r})"
        )
        assert msg == MSG_LOGINS_DONT_MATCH, (
            f"{op}'s refusal must be the login-mismatch one ({MSG_LOGINS_DONT_MATCH!r}), which ties "
            f"it to the unlink rather than to a generic authorization failure: {msg!r}"
        )

    # --- positive control AFTER: the sibling identity, same pool, same provider, still works ---
    sib_open = ci.get_open_id_token(IdentityId=sibling_id, Logins={provider: token_sibling})
    assert sib_open["IdentityId"] == sibling_id, (
        f"sibling GetOpenIdToken answered for {sib_open['IdentityId']!r}, not {sibling_id!r}"
    )
    sib_vend = ci.get_credentials_for_identity(IdentityId=sibling_id, Logins={provider: token_sibling})
    assert sib_vend["IdentityId"] == sibling_id, (
        f"sibling credentials were vended for {sib_vend['IdentityId']!r}, not {sibling_id!r}"
    )
    c = sib_vend["Credentials"]
    arn = _caller_arn(c["AccessKeyId"], c["SecretKey"], c["SessionToken"])
    assert arn == _assumed_arn(CREDENTIALS_SESSION), (
        f"sibling credentials must authenticate as {_assumed_arn(CREDENTIALS_SESSION)!r}, got {arn!r}"
    )

    # --- effect absent: the refused calls minted no identity -----------------------------------
    listed = _list_identities(ci, pool_id)
    assert listed == {orphan_id: [DISABLED], sibling_id: [provider]}, (
        f"the pool must hold exactly the orphan and the sibling, got {listed!r}"
    )

    # --- what unlinking does NOT revoke: it removes the mapping, not already-issued tokens -----
    still = ci.get_credentials_for_identity(IdentityId=orphan_id, Logins={COGNITO_LOGIN: pre_openid_token})
    assert still["IdentityId"] == orphan_id, (
        f"the orphan's pre-unlink OpenID token must still vend credentials for {orphan_id!r}, got "
        f"{still['IdentityId']!r}"
    )
    re_assumed = sts.assume_role_with_web_identity(
        RoleArn=role_arn, RoleSessionName="sim2real-post-unlink", WebIdentityToken=pre_openid_token)
    assert re_assumed["SubjectFromWebIdentityToken"] == orphan_id, (
        f"STS must still accept the orphan's pre-unlink token as subject {orphan_id!r}, got "
        f"{re_assumed['SubjectFromWebIdentityToken']!r}"
    )
    arn = _caller_arn(pre_session["AccessKeyId"], pre_session["SecretAccessKey"],
                      pre_session["SessionToken"])
    assert arn == _assumed_arn(pre_session_name), (
        f"the pre-unlink STS session must still authenticate after the unlink, got {arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
