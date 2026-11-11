"""xsvc-cognito-identity-2-iam-oidc-registered-user-pool-issuer-vends-sts-credentials."""
from __future__ import annotations

import base64
import json
import time
import uuid
from urllib.parse import urlparse

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-2-iam-oidc-registered-user-pool-issuer-vends-sts-credentials"
GROUP = "oidc-federation"
SERVICES = ["cognito-identity", "cognito-idp", "iam"]

_PROPAGATION_S = 180.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=_PROPAGATION_S, interval_s=3.0, description="condition"):
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


def _jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _issuer_key(token):
    """The Logins key for an OIDC provider is the issuer without its scheme, parsed structurally."""
    iss = _jwt_claims(token)["iss"]
    parsed = urlparse(iss)
    assert parsed.scheme == "https" and parsed.netloc, f"token iss {iss!r} is not an https URL"
    return iss, parsed.netloc + parsed.path


def _user_pool(ctx, idp, label, n_clients=1):
    """A user pool with n app clients and one confirmed user; returns (pool, clients, mint)."""
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name(f"sim2real-xsvc-{label}-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    clients = [
        idp.create_user_pool_client(
            UserPoolId=pool_id, ClientName=f"sim2real-xsvc-{label}-{i}", GenerateSecret=False,
            ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        )["UserPoolClient"]["ClientId"]
        for i in range(n_clients)
    ]
    username = ctx.unique_name(f"sim2real-xsvc-{label}-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )

    def mint(client_id):
        return idp.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]

    return pool_id, clients, mint


def _register_oidc(ctx, iam, issuer_url, client_ids):
    arn = iam.create_open_id_connect_provider(
        Url=issuer_url, ClientIDList=list(client_ids),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))
    return arn


def _cognito_trust_policy(pool_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    })


def _authenticated_role(ctx, iam, ci, pool_id, label):
    name = ctx.unique_name(f"sim2real-xsvc-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_cognito_trust_policy(pool_id),
        Description="sim2real cross-service probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    deadline = time.time() + _PROPAGATION_S
    while True:
        try:
            ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": arn})
            return name
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


def _identity_ids(ci, pool_id):
    ids, token = [], None
    while True:
        kw = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if token:
            kw["NextToken"] = token
        page = ci.list_identities(**kw)
        ids += [i["IdentityId"] for i in page.get("Identities", [])]
        token = page.get("NextToken")
        if not token:
            return ids


@tags("axis:happy-path", "cap:c7", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A user pool issuer registered as an IAM OIDC provider and referenced only through
    OpenIdConnectProviderARNs federates the pool's ID token: GetId mints an identity and the
    vended credentials resolve at STS to the pool's authenticated role.
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    user_pool, (client_id,), mint = _user_pool(ctx, idp, "oidc-up")
    token = mint(client_id)
    issuer_url, issuer_key = _issuer_key(token)
    assert issuer_key.endswith("/" + user_pool), (
        f"the token's issuer {issuer_url!r} must name the user pool {user_pool!r}"
    )
    assert _jwt_claims(token)["aud"] == client_id, (
        f"ID token aud {_jwt_claims(token).get('aud')!r} must be the app client {client_id!r}"
    )

    provider_arn = _register_oidc(ctx, iam, issuer_url, [client_id])
    described_provider = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert described_provider["Url"] == issuer_key, (
        f"IAM must store the provider Url without scheme as {issuer_key!r}, "
        f"got {described_provider.get('Url')!r}"
    )
    assert described_provider["ClientIDList"] == [client_id], (
        f"IAM ClientIDList must be [{client_id!r}], got {described_provider.get('ClientIDList')!r}"
    )

    pool_name = ctx.unique_name("sim2real_xsvc_oidc_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name, AllowUnauthenticatedIdentities=False,
        OpenIdConnectProviderARNs=[provider_arn], IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    described_pool = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described_pool.get("OpenIdConnectProviderARNs") == [provider_arn], (
        f"DescribeIdentityPool must echo OpenIdConnectProviderARNs=[{provider_arn!r}], "
        f"got {described_pool.get('OpenIdConnectProviderARNs')!r}"
    )
    assert not described_pool.get("CognitoIdentityProviders"), (
        f"the pool must federate through IAM only, but lists CognitoIdentityProviders "
        f"{described_pool.get('CognitoIdentityProviders')!r}"
    )
    role_name = _authenticated_role(ctx, iam, ci, pool_id, "oidc-auth")

    logins = {issuer_key: token}
    identity_id = _poll_until(
        lambda: ci.get_id(IdentityPoolId=pool_id, Logins=logins),
        lambda r: bool(r.get("IdentityId")),
        description="GetId to admit the IAM-registered issuer",
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    assert identity_id.startswith(ctx.region + ":"), (
        f"IdentityId {identity_id!r} must be scoped to region {ctx.region!r}"
    )

    # GetId is idempotent for the same login: the same identity, not a second one.
    again = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    assert again == identity_id, f"a repeat GetId minted {again!r}, expected {identity_id!r}"
    listed = _poll_until(
        lambda: _identity_ids(ci, pool_id), lambda ids: identity_id in ids,
        description="ListIdentities to show the federated identity",
    )
    assert listed == [identity_id], (
        f"the pool must hold exactly the one identity, got {listed!r}"
    )

    vended = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
        lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
        description="GetCredentialsForIdentity to vend for the IAM-federated login",
    )
    assert vended["IdentityId"] == identity_id, (
        f"credentials were vended for {vended.get('IdentityId')!r}, not {identity_id!r}"
    )
    creds = vended["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA"), (
        f"vended credentials must be temporary STS keys (ASIA…), got {creds['AccessKeyId'][:4]!r}"
    )
    arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in arn, (
        f"the vended keys must be a session of the authenticated role {role_name!r}, got {arn!r}"
    )

    described_identity = ci.describe_identity(IdentityId=identity_id)
    assert described_identity.get("Logins") == [issuer_key], (
        f"DescribeIdentity must record the login under the issuer key {issuer_key!r}, got "
        f"{described_identity.get('Logins')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
