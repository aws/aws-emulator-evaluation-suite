"""xsvc-cognito-identity-2-oidc-client-id-missing-from-iam-provider-rejected."""
from __future__ import annotations

import base64
import json
import time
import uuid
from urllib.parse import urlparse

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-2-oidc-client-id-missing-from-iam-provider-rejected"
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


def _error(fn):
    """The AWS error (code, message) fn() raises. An unexpected SUCCESS is raised, never returned."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_for_refusal(fn, timeout_s=_PROPAGATION_S, interval_s=3.0, description="refusal"):
    """Retry FOR a refusal and return its (code, message); a propagation window is the only
    reason it could be late."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"{description} never arrived within {timeout_s}s; last success {last!r}")


def _vends(ci, identity_id, logins, description):
    return _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
        lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
        description=description,
    )["Credentials"]


def _federate(ctx, ci, pool_id, logins, description):
    identity_id = _poll_until(
        lambda: ci.get_id(IdentityPoolId=pool_id, Logins=logins),
        lambda r: bool(r.get("IdentityId")),
        description=description,
    )["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    return identity_id


def _oidc_pool(ctx, ci, provider_arns):
    name = ctx.unique_name("sim2real_xsvc_oidc_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=False,
        OpenIdConnectProviderARNs=list(provider_arns), IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id, name


def _session_role(ctx, creds):
    return _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IAM's ClientIDList gates the token audience: an unlisted app client's token is refused
    NotAuthorizedException while a listed client of the same pool federates; adding the client
    admits it, and removing the first client then shuts that one out.
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    _, (listed_client, unlisted_client), mint = _user_pool(ctx, idp, "aud", n_clients=2)
    listed_token, unlisted_token = mint(listed_client), mint(unlisted_client)
    issuer, key = _issuer_key(listed_token)
    assert _issuer_key(unlisted_token)[1] == key, "both clients' tokens must share one issuer"
    assert _jwt_claims(unlisted_token)["aud"] == unlisted_client, (
        f"the second token's aud must be {unlisted_client!r}, got {_jwt_claims(unlisted_token).get('aud')!r}"
    )
    provider_arn = _register_oidc(ctx, iam, issuer, [listed_client])

    pool_id, _ = _oidc_pool(ctx, ci, [provider_arn])
    role_name = _authenticated_role(ctx, iam, ci, pool_id, "aud-auth")

    # ---- barrier + positive control: the listed client's token federates and vends, proving the
    # provider has propagated, so the later refusal can only come from the audience check.
    identity_id = _federate(ctx, ci, pool_id, {key: listed_token}, "GetId for the listed client")
    arn = _session_role(ctx, _vends(ci, identity_id, {key: listed_token}, "the listed client"))
    assert f":assumed-role/{role_name}/" in arn, f"control must vend {role_name!r}, got {arn!r}"

    # ---- the one difference: the token's audience is not on IAM's ClientIDList.
    code, message = _error(lambda: ci.get_id(IdentityPoolId=pool_id, Logins={key: unlisted_token}))
    assert code == "NotAuthorizedException", (
        f"GetId for an audience missing from ClientIDList must be refused NotAuthorizedException, "
        f"got {code!r}"
    )
    expected = "Invalid login token. Incorrect token audience."
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"
    code, message = _error(lambda: ci.get_credentials_for_identity(
        IdentityId=identity_id, Logins={key: unlisted_token}))
    assert code == "NotAuthorizedException", (
        f"GetCredentialsForIdentity for an unlisted audience must be refused "
        f"NotAuthorizedException, got {code!r}"
    )
    expected = "Invalid login token. Incorrect token audience."
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"
    listed = _poll_until(
        lambda: _identity_ids(ci, pool_id), lambda ids: identity_id in ids,
        description="ListIdentities to show the federated identity",
    )
    assert listed == [identity_id], f"the refusal must mint nothing; pool holds {listed!r}"

    # ---- repair in IAM: admit the second client, and the same token now federates — to the
    # same identity, because the identity is the user, not the app client.
    iam.add_client_id_to_open_id_connect_provider(
        OpenIDConnectProviderArn=provider_arn, ClientID=unlisted_client,
    )
    stored = sorted(iam.get_open_id_connect_provider(
        OpenIDConnectProviderArn=provider_arn)["ClientIDList"])
    assert stored == sorted([listed_client, unlisted_client]), (
        f"IAM ClientIDList must now hold both clients, got {stored!r}"
    )
    repaired = _poll_until(
        lambda: ci.get_id(IdentityPoolId=pool_id, Logins={key: unlisted_token}),
        lambda r: bool(r.get("IdentityId")),
        description="the added client to federate",
    )["IdentityId"]
    assert repaired == identity_id, (
        f"the same user through a second client must resolve to {identity_id!r}, got {repaired!r}"
    )
    arn = _session_role(ctx, _vends(ci, identity_id, {key: unlisted_token}, "the added client"))
    assert f":assumed-role/{role_name}/" in arn, f"the added client must vend {role_name!r}, got {arn!r}"

    # ---- and the gate is live in the other direction: remove the first client.
    iam.remove_client_id_from_open_id_connect_provider(
        OpenIDConnectProviderArn=provider_arn, ClientID=listed_client,
    )
    code, message = _poll_for_refusal(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins={key: listed_token}),
        description="the vend refusal after removing the first client from ClientIDList",
    )
    assert code == "NotAuthorizedException", (
        f"a client removed from ClientIDList must be refused NotAuthorizedException, got {code!r}"
    )
    expected = "Invalid login token. Incorrect token audience."
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"
    arn = _session_role(ctx, _vends(ci, identity_id, {key: unlisted_token}, "the remaining client"))
    assert f":assumed-role/{role_name}/" in arn, (
        f"the client still on ClientIDList must keep vending {role_name!r}, got {arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
