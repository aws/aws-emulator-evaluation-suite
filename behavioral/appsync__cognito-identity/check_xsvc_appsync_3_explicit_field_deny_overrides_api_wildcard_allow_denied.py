"""xsvc-appsync-3-explicit-field-deny-overrides-api-wildcard-allow-denied."""
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

CHECK = "xsvc-appsync-3-explicit-field-deny-overrides-api-wildcard-allow-denied"
GROUP = "overly-permissive"
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
    """Bounded retry that raises on timeout instead of returning its last value."""
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
    A 4xx is returned; a transport failure fails as a missing GraphQL data plane."""
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


def _grant_api_wildcard_deny_field(ctx, role_name, api_arn, denied_field_arn):
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name, PolicyName="appsync-wildcard-allow-field-deny",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "appsync:GraphQL", "Resource": f"{api_arn}/*"},
                {"Effect": "Deny", "Action": "appsync:GraphQL", "Resource": denied_field_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(
        RoleName=role_name, PolicyName="appsync-wildcard-allow-field-deny"))


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
    """Poll a signed query to 200 while the role policy propagates, with fresh credentials each
    attempt: a session refused before propagation can stay refused well past it."""
    def _probe():
        creds = _credentials(ctx, identity_id, logins)
        return creds, _post_signed(ctx, url, creds, query)

    return _poll_until(
        _probe, lambda r: r[1][0] == 200, timeout_s=240.0, interval_s=6.0,
        description=f"the signed query {query!r} to be admitted once the role policy propagates",
    )


def _assert_request_refused(status, headers, body, what):
    """The whole-request IAM refusal AppSync returns: 401, one UnauthorizedException, no data."""
    assert status == 401, f"{what}: expected HTTP 401, got {status!r} body={body!r}"
    assert headers.get("x-amzn-errortype") == "UnauthorizedException", (
        f"{what}: expected x-amzn-ErrorType UnauthorizedException, got "
        f"{headers.get('x-amzn-errortype')!r}"
    )
    errors = body.get("errors") or []
    assert len(errors) == 1, f"{what}: expected exactly one error, got {errors!r}"
    assert errors[0].get("errorType") == "UnauthorizedException", (
        f"{what}: expected errorType UnauthorizedException, got {errors[0].get('errorType')!r}"
    )
    assert errors[0].get("message") == "Permission denied", (
        f"{what}: expected message 'Permission denied', got {errors[0].get('message')!r}"
    )
    assert "data" not in body, (
        f"{what}: a refused request must carry no data envelope; got keys {sorted(body)!r}"
    )



@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An explicit Deny on one Query field beats an api-wide wildcard Allow: `{ other }` gets a 401
    UnauthorizedException, `{ allowed }` is served, and a mixed query is a partial result.
    """
    _api_id, api_arn, url = _iam_graphql_api(ctx)
    pool_id, developer = _identity_pool(ctx)
    auth_role, auth_arn = _federated_role(ctx, pool_id, "authenticated")
    _grant_api_wildcard_deny_field(
        ctx, auth_role, api_arn, f"{api_arn}/types/Query/fields/other")
    _unauth_role, unauth_arn = _federated_role(ctx, pool_id, "unauthenticated")
    cid = ctx.client("cognito-identity")
    cid.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"authenticated": auth_arn, "unauthenticated": unauth_arn},
    )
    identity_id, _login, logins = _authenticated_identity(ctx, pool_id, developer)

    creds, (status, _headers, body) = _signed_until_ok(ctx, url, identity_id, logins, "{ allowed }")
    assert status == 200 and not body.get("errors"), (
        f"positive control: the wildcard-allowed field was not served cleanly: {status!r} {body!r}"
    )
    echoed = json.loads((body.get("data") or {}).get("allowed") or "{}")
    assert echoed.get("cognitoIdentityId") == identity_id, (
        f"positive control resolved for the wrong identity: expected {identity_id!r}, got {echoed!r}"
    )

    status, headers, body = _post_signed(ctx, url, creds, "{ other }")
    _assert_request_refused(status, headers, body, "explicitly denied field `other`")

    # The refused field has a resolver, so the Deny is the only cause.
    resolver = ctx.client("appsync").get_resolver(
        apiId=_api_id, typeName="Query", fieldName="other")["resolver"]
    assert resolver.get("fieldName") == "other", (
        f"the `other` resolver is missing, so the refusal would prove nothing: {resolver!r}"
    )

    status, _headers, body = _post_signed(ctx, url, creds, "{ allowed other }")
    assert status == 200, f"mixed request: expected HTTP 200 partial result, got {status!r} {body!r}"
    data = body.get("data") or {}
    assert json.loads(data.get("allowed") or "{}").get("cognitoIdentityId") == identity_id, (
        f"mixed request: the wildcard-allowed field did not resolve for this identity: {data!r}"
    )
    assert "other" in data and data["other"] is None, (
        f"mixed request: the denied field must be present and null, got {data!r}"
    )
    errors = body.get("errors") or []
    assert len(errors) == 1, f"mixed request: expected exactly one error, got {errors!r}"
    assert errors[0].get("path") == ["other"], (
        f"mixed request: the error must name the denied field, got {errors[0]!r}"
    )
    assert errors[0].get("errorType") == "Unauthorized", (
        f"mixed request: expected field-level errorType 'Unauthorized', got "
        f"{errors[0].get('errorType')!r} in {errors[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
