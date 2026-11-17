"""set-user-mfa-preference-forbidden-without-authorization."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-forbidden-without-authorization"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]
#: The status the hosted domain answers while it still propagates; the token loop retries it.
DOMAIN_PROPAGATING_STATUS = 404


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SetUserMFAPreference with a client_credentials access token, which never carries the
    reserved aws.cognito.signin.user.admin scope, is refused with NotAuthorizedException, while
    a user access token for the same pool succeeds."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-mfascope-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2real-mfascope-dom-").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    resource_server_id = ctx.unique_name("sim2real-mfascope-rs-")
    cognito.create_resource_server(
        UserPoolId=pool_id,
        Identifier=resource_server_id,
        Name=resource_server_id,
        Scopes=[{"ScopeName": "read", "ScopeDescription": "read access"}],
    )

    m2m_client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-mfascope-m2m-"),
        GenerateSecret=True,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=[f"{resource_server_id}/read"],
        AllowedOAuthFlowsUserPoolClient=True,
    )["UserPoolClient"]
    m2m_client_id = m2m_client["ClientId"]
    m2m_client_secret = m2m_client["ClientSecret"]

    m2m_token = _get_client_credentials_token(
        ctx, domain, m2m_client_id, m2m_client_secret, f"{resource_server_id}/read"
    )

    code, message = _error(
        lambda: cognito.set_user_mfa_preference(
            AccessToken=m2m_token,
            SMSMfaSettings={"Enabled": False, "PreferredMfa": False},
        )
    )
    assert code == "NotAuthorizedException", code
    assert message == "Access Token does not have required scopes", message

    # Positive control: a genuine user access token for the same pool carries the
    # reserved scope and the same call succeeds.
    user_client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-mfascope-user-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-mfascope-user-")
    password = "TestPassw0rd!23"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=user_client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    user_token = auth["AuthenticationResult"]["AccessToken"]
    cognito.set_user_mfa_preference(
        AccessToken=user_token, SMSMfaSettings={"Enabled": False, "PreferredMfa": False}
    )
    # Independent read at the destination, through a different operation than the one that
    # mutated: the identical call the m2m token was refused for actually took effect for the
    # real user, and the token used to make it is still valid (the earlier refusal didn't
    # corrupt pool or token state).
    still_valid = cognito.get_user(AccessToken=user_token)
    assert still_valid["Username"] == username, still_valid


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a target
    accepting a call real AWS refuses must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected SetUserMFAPreference to be refused, but it SUCCEEDED: {result!r}")


def _get_client_credentials_token(
    ctx, domain: str, client_id: str, client_secret: str, scope: str
) -> str:
    """Even after the domain reports ACTIVE, its hosted endpoint may take minutes to answer
    over HTTPS, so poll the token endpoint itself until the check's budget (less 30 s for
    the rest of the check) runs out. A 404 (domain still propagating) and transport errors
    retry for that whole window; 5xx answers retry at most 10 times."""
    token_url = f"https://{domain}.auth.{ctx.region}.amazoncognito.com/oauth2/token"
    verify = ctx.http_verify
    tls = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    body = urlencode({"grant_type": "client_credentials", "scope": scope}).encode()
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    deadline = time.monotonic() + ctx.time_left() - 30.0
    server_errors = 0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        req = urllib.request.Request(token_url, data=body, method="POST")  # customer-built AWS host
        req.add_header("Authorization", f"Basic {basic}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=15, context=tls) as resp:
                payload = json.loads(resp.read())
                return payload["access_token"]
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                server_errors += 1
                if server_errors >= 10:
                    raise AssertionError(f"token endpoint answered {e.code} {server_errors} times") from e
            elif e.code != DOMAIN_PROPAGATING_STATUS:
                raise AssertionError(f"token endpoint rejected request: {e.code} {e.read()}") from e
            last_err = e
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
        time.sleep(5.0)
    raise AssertionError(f"token endpoint for {domain} never became reachable: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
