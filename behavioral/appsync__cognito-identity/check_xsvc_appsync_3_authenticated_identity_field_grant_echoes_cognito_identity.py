"""xsvc-appsync-3-authenticated-identity-field-grant-echoes-cognito-identity."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-appsync-3-authenticated-identity-field-grant-echoes-cognito-identity"
GROUP = "iam-trust"
SERVICES = ["appsync", "cognito-identity"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Both fields have a resolver, so a refusal of either can only come from the IAM policy, never
# from an unresolvable field.
SDL = """schema { query: Query }
type Query {
    allowed: AWSJSON
    other: AWSJSON
}
"""

# A NONE data source: no backing service, the request template's payload IS the result.
ECHO_IDENTITY_REQUEST = '{"version": "2018-05-29", "payload": $util.toJson($context.identity)}'
ECHO_IDENTITY_RESPONSE = "$util.toJson($context.result)"


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_signed(ctx, url, creds, query):
    """SigV4-sign a GraphQL POST with Cognito-vended credentials -> (status, headers, body).

    A 4xx is a RESULT. A transport failure means no GraphQL endpoint answered at all, which is a
    missing data plane rather than a policy decision, so it fails with the data-plane sentinel.
    """
    body = json.dumps({"query": query}).encode()
    signer = Credentials(creds["AccessKeyId"], creds["SecretKey"], creds["SessionToken"])
    request = AWSRequest(method="POST", url=url, data=body,
                         headers={"Content-Type": "application/json"})
    SigV4Auth(signer, "appsync", ctx.region).add_auth(request)
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, method="POST", headers={**dict(request.headers), **route_headers})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, headers, raw = resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as exc:
        status, headers, raw = exc.code, dict(exc.headers), exc.read().decode()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the GraphQL endpoint {url!r} did not answer: {exc!r}"
        ) from exc
    try:
        parsed = json.loads(raw) if raw else {}
    except ValueError:
        parsed = {"raw": raw}
    return status, {k.lower(): v for k, v in headers.items()}, parsed


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(
                f"role {role_name} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _iam_graphql_api(ctx):
    """An AWS_IAM GraphQL api, both Query fields resolved by a NONE identity echo."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-xsvc-appsync3-"),
        authenticationType="AWS_IAM",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=SDL.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: got {status['status']!r} {status.get('details')!r}"
    )
    ds_name = _alnum(ctx, "none_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    for field in ("allowed", "other"):
        svc.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field, dataSourceName=ds_name,
            requestMappingTemplate=ECHO_IDENTITY_REQUEST,
            responseMappingTemplate=ECHO_IDENTITY_RESPONSE,
        )
        ctx.on_cleanup(
            lambda f=field: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName=f)
        )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    return api_id, api["arn"], uri


def _identity_pool(ctx):
    """An identity pool with a developer provider and unauthenticated identities enabled."""
    cid = ctx.client("cognito-identity")
    developer = ctx.unique_name("sim2real.xsvc.appsync3.")
    pool_id = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_xsvc_appsync3_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id, developer


def _federated_role(ctx, pool_id, amr):
    """A role only this pool's ``amr`` identities can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-xsvc-appsync3-{amr[:5]}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
            },
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    return role_name, arn


def _grant_one_field(ctx, role_name, field_arn):
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name, PolicyName="appsync-graphql-one-field",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": field_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(
        RoleName=role_name, PolicyName="appsync-graphql-one-field"))


def _credentials(ctx, identity_id, logins=None, timeout_s=90.0):
    """GetCredentialsForIdentity, retried only while the pool's role wiring is still settling."""
    cid = ctx.client("cognito-identity")
    kwargs = {"IdentityId": identity_id}
    if logins:
        kwargs["Logins"] = logins
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cid.get_credentials_for_identity(**kwargs)["Credentials"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidIdentityPoolConfigurationException" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _authenticated_identity(ctx, pool_id, developer):
    """GetId, then link a developer login to that SAME identity -> (identity_id, login, logins)."""
    cid = ctx.client("cognito-identity")
    identity_id = cid.get_id(IdentityPoolId=pool_id)["IdentityId"]
    login = ctx.unique_name("user-")
    linked = cid.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, IdentityId=identity_id, Logins={developer: login},
    )
    assert linked["IdentityId"] == identity_id, (
        f"linking a developer login to the GetId identity must keep its id: GetId returned "
        f"{identity_id!r}, GetOpenIdTokenForDeveloperIdentity returned {linked['IdentityId']!r}"
    )
    return identity_id, login, {"cognito-identity.amazonaws.com": linked["Token"]}


def _signed_until_ok(ctx, url, identity_id, logins, query):
    """Poll a signed query to 200 while the role policy propagates.

    Fresh credentials on every attempt: a session that was refused before its role policy became
    effective can stay refused well past propagation (observed: >150 s), so re-using it would
    turn IAM propagation into a false failure.
    """
    def _probe():
        creds = _credentials(ctx, identity_id, logins)
        return creds, _post_signed(ctx, url, creds, query)

    return _poll_until(
        _probe, lambda r: r[1][0] == 200, timeout_s=240.0, interval_s=6.0,
        description=f"the signed query {query!r} to be admitted once the role policy propagates",
    )


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """An identity-pool AUTHENTICATED identity reaches the one field its role was granted.

    AppSync's $context.identity echo must name this pool, this Cognito identity, its
    "authenticated" authType, the linked developer login, and the authenticated role's ARN.
    """
    _api_id, api_arn, url = _iam_graphql_api(ctx)
    pool_id, developer = _identity_pool(ctx)
    auth_role, auth_arn = _federated_role(ctx, pool_id, "authenticated")
    _grant_one_field(ctx, auth_role, f"{api_arn}/types/Query/fields/allowed")
    unauth_role, unauth_arn = _federated_role(ctx, pool_id, "unauthenticated")
    cid = ctx.client("cognito-identity")
    cid.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"authenticated": auth_arn, "unauthenticated": unauth_arn},
    )
    # fixed-wait: a head start before IAM role-policy propagation; not a correctness bound --
    # the bounded retry at first use is what makes the check correct even if this is too short.
    time.sleep(10)

    # ---- beat 1: GetId, then authenticate that same identity --------------------------------
    identity_id, login, logins = _authenticated_identity(ctx, pool_id, developer)
    described = cid.describe_identity(IdentityId=identity_id)
    assert developer in (described.get("Logins") or []), (
        f"DescribeIdentity does not list the linked developer provider {developer!r}: "
        f"{described.get('Logins')!r}"
    )
    try:
        cid.get_credentials_for_identity(IdentityId=identity_id)
        raise AssertionError(
            "an AUTHENTICATED identity was vended credentials without presenting any login"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "NotAuthorizedException", (
            f"expected NotAuthorizedException for login-less credentials on an authenticated "
            f"identity, got {code!r}: {exc.response.get('Error')!r}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == f"Access to Identity '{identity_id}' is forbidden.", (
            f"login-less credentials refusal carries the wrong message: {message!r}"
        )

    # ---- beat 2: the granted field is admitted ----------------------------------------------
    _creds, (status, _headers, body) = _signed_until_ok(
        ctx, url, identity_id, logins, "{ allowed }")
    assert status == 200 and not body.get("errors"), (
        f"the granted field was not served cleanly: {status!r} {body!r}"
    )
    raw = (body.get("data") or {}).get("allowed")
    assert isinstance(raw, str), f"expected the AWSJSON echo as a JSON string, got {raw!r}"
    identity = json.loads(raw)

    # ---- beat 3: AppSync saw exactly the Cognito identity the pool vended -------------------
    assert identity.get("cognitoIdentityPoolId") == pool_id, (
        f"cognitoIdentityPoolId: expected {pool_id!r}, got {identity.get('cognitoIdentityPoolId')!r}"
    )
    assert identity.get("cognitoIdentityId") == identity_id, (
        f"cognitoIdentityId: expected the GetId id {identity_id!r}, got "
        f"{identity.get('cognitoIdentityId')!r}"
    )
    assert identity.get("cognitoIdentityAuthType") == "authenticated", (
        f"cognitoIdentityAuthType: expected 'authenticated', got "
        f"{identity.get('cognitoIdentityAuthType')!r} in {identity!r}"
    )
    expected_provider = f'"{developer}","{developer}:{pool_id}:{login}"'
    assert identity.get("cognitoIdentityAuthProvider") == expected_provider, (
        f"cognitoIdentityAuthProvider: expected {expected_provider!r}, got "
        f"{identity.get('cognitoIdentityAuthProvider')!r}"
    )
    partition, account = api_arn.split(":")[1], api_arn.split(":")[4]
    assert identity.get("accountId") == account, (
        f"accountId: expected {account!r}, got {identity.get('accountId')!r}"
    )
    expected_user_arn = (
        f"arn:{partition}:sts::{account}:assumed-role/{auth_role}/CognitoIdentityCredentials"
    )
    assert identity.get("userArn") == expected_user_arn, (
        f"userArn: expected the authenticated role's session {expected_user_arn!r}, got "
        f"{identity.get('userArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
