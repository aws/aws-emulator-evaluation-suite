"""appsync-http-data-source-sigv4-signs-request-to-api-gateway."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.parse
import urllib.request

from behavioral_harness import tags

CHECK = "appsync-http-data-source-sigv4-signs-request-to-api-gateway"
GROUP = "methods-integrations"
SERVICES = ["apigateway", "appsync"]

# Bounds both the new IAM role becoming assumable by AppSync and the stage becoming servable.
_ROLE_PROPAGATION_S = 300.0

SDL = """schema { query: Query }
type Query {
    openViaUnsigned: String
    guardedViaSigned: String
    guardedViaUnsigned: String
}
"""


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _alnum(ctx, prefix):
    """A unique name with NO hyphens — AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*``."""
    return ctx.unique_name(prefix).replace("-", "_")


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _ignore_not_found(fn):
    """Teardown helper: already-gone is not a cleanup failure; anything else still raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException",
                                                "ResourceNotFoundException", "NoSuchEntity"):
            raise


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Bounded retry; RAISES on the deadline rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST a JSON body with stdlib urllib -> (status, parsed_body, headers).

    A transport-level failure returns status None so callers can keep polling a warming
    endpoint instead of failing on the first DNS/TLS miss; None is never a passing value."""
    data = json.dumps(payload).encode()
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(
        _url, data=data, method="POST",
        headers={**({"Content-Type": "application/json", **headers}), **_route},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - fixed scheme
            status, raw, hdrs = resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        status, raw, hdrs = exc.code, exc.read().decode(errors="replace"), dict(exc.headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}, {}
    try:
        return status, (json.loads(raw) if raw else {}), hdrs
    except ValueError:
        return status, {"raw": raw}, hdrs


def _gql(ctx, url, api_key, query):
    return _post_json(ctx, url, {"x-api-key": api_key}, {"query": query})


def _graphql_endpoint(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + active schema + api key -> (api_id, graphql_url, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY", tags={"sim2real": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: _ignore_not_found(
        lambda: svc.delete_graphql_api(apiId=_a["apiId"])))
    api_id = api["apiId"]
    url = (api.get("uris") or {}).get("GRAPHQL")
    if not url:
        raise AssertionError(f"GraphQL API exposed no GRAPHQL endpoint URI: {api!r}")
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=120, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal state",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: status={status['status']!r} "
        f"details={status.get('details')!r}"
    )
    key = svc.create_api_key(
        apiId=api_id, description="sim2real-behav graphql key")["apiKey"]["id"]
    return api_id, url, key


def _origin(ctx, rest_api_id, stage):
    """(endpoint, path_prefix) of the deployed REST stage's invoke URL, split the way an AppSync
    HTTP data source takes it: the origin as `httpConfig.endpoint`, the path as the prefix of
    every resolver's `resourcePath`."""
    url = urllib.parse.urlsplit(ctx.rest_api_url(rest_api_id, stage))
    return f"{url.scheme}://{url.netloc}", url.path


def _mock_get(ag, api_id, resource_id, marker, authorization_type):
    """A GET method whose MOCK integration returns {"marker": marker} on 200."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType=authorization_type))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"marker":"%s"}' % marker}))


# The response template renders the UPSTREAM STATUS into the GraphQL error, so a refusal is
# attributable to API Gateway rather than to AppSync giving up. A non-2xx is deliberately not
# treated as a resolver crash: $ctx.result carries the status for any response.
_RESPONSE_TEMPLATE = (
    "#if($ctx.result.statusCode == 200)\n"
    "$util.toJson($util.parseJson($ctx.result.body).marker)\n"
    "#else\n"
    '$util.error("upstream-status-$ctx.result.statusCode", "UpstreamStatusError")\n'
    "#end"
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AppSync HTTP data source with awsIamConfig SigV4-signs its request, so an AWS_IAM API
    Gateway method admits it, while an otherwise identical unsigned data source is refused 403 in
    the same GraphQL request; adding the config via UpdateDataSource makes the same query resolve.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/tutorial-http-resolvers.html
    """
    ag = ctx.client("apigateway")
    iam = ctx.client("iam")
    svc = ctx.client("appsync")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    marker = f"sim2real-{_unique_token()}"

    # ---- the origin: one REST API, one AWS_IAM method and one open method ---------------
    rest_api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_rest_api(restApiId=rest_api_id)))

    resources = {}
    for path_part, auth in (("iamguard", "AWS_IAM"), ("open", "NONE")):
        resource_id = _retry_throttled(lambda pp=path_part: ag.create_resource(
            restApiId=rest_api_id, parentId=_root_id(ag, rest_api_id), pathPart=pp))["id"]
        resources[path_part] = resource_id
        ctx.on_cleanup(lambda rid=resource_id: _retry_throttled(
            lambda: ag.delete_resource(restApiId=rest_api_id, resourceId=rid)))
        _mock_get(ag, rest_api_id, resource_id, marker, auth)

    guarded_method = ag.get_method(restApiId=rest_api_id,
                                   resourceId=resources["iamguard"], httpMethod="GET")
    assert guarded_method.get("authorizationType") == "AWS_IAM", (
        f"precondition: the guarded method must really require SigV4, but GetMethod reported "
        f"authorizationType={guarded_method.get('authorizationType')!r}"
    )

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=rest_api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=rest_api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=rest_api_id, stageName=stage)))
    endpoint, path_prefix = _origin(ctx, rest_api_id, stage)

    # ---- the identity AppSync signs with ------------------------------------------------
    role_name = ctx.unique_name("sim2real-behav-appsynchttp-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "appsync.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="invoke-execute-api",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": "execute-api:Invoke",
                "Resource": (f"arn:aws:execute-api:{ctx.region}:{account_id}:"
                             f"{rest_api_id}/*/*/*"),
            }],
        }))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role_policy(
        RoleName=role_name, PolicyName="invoke-execute-api")))

    # ---- the consumer: two data sources differing ONLY in the signing config ------------
    gql_api_id, gql_url, gql_key = _graphql_endpoint(ctx, svc, SDL)

    signing = {"authorizationType": "AWS_IAM",
               "awsIamConfig": {"signingRegion": ctx.region,
                                "signingServiceName": "execute-api"}}
    signed_name = _alnum(ctx, "ds_signed_")
    svc.create_data_source(
        apiId=gql_api_id, name=signed_name, type="HTTP", serviceRoleArn=role_arn,
        httpConfig={"endpoint": endpoint, "authorizationConfig": signing})
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: svc.delete_data_source(apiId=gql_api_id, name=signed_name)))

    unsigned_name = _alnum(ctx, "ds_unsigned_")
    svc.create_data_source(
        apiId=gql_api_id, name=unsigned_name, type="HTTP",
        httpConfig={"endpoint": endpoint})
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: svc.delete_data_source(apiId=gql_api_id, name=unsigned_name)))

    stored_signed = svc.get_data_source(apiId=gql_api_id, name=signed_name)["dataSource"]
    stored_iam = ((stored_signed.get("httpConfig") or {}).get("authorizationConfig")
                  or {}).get("awsIamConfig") or {}
    assert stored_iam.get("signingServiceName") == "execute-api", (
        f"precondition: GetDataSource must report the signing config as stored, got "
        f"httpConfig={stored_signed.get('httpConfig')!r}"
    )
    stored_unsigned = svc.get_data_source(apiId=gql_api_id, name=unsigned_name)["dataSource"]
    assert not (stored_unsigned.get("httpConfig") or {}).get("authorizationConfig"), (
        f"precondition: the twin must differ ONLY by having no authorizationConfig, got "
        f"httpConfig={stored_unsigned.get('httpConfig')!r}"
    )

    for field, ds_name, path_part in (
        ("guardedViaSigned", signed_name, "iamguard"),
        ("guardedViaUnsigned", unsigned_name, "iamguard"),
        ("openViaUnsigned", unsigned_name, "open"),
    ):
        svc.create_resolver(
            apiId=gql_api_id, typeName="Query", fieldName=field, kind="UNIT",
            dataSourceName=ds_name,
            requestMappingTemplate=json.dumps({
                "version": "2018-05-29", "method": "GET",
                "resourcePath": f"{path_prefix}/{path_part}",
                # AppSync's HTTP resolver defaults an unset Content-Type to
                # application/octet-stream, which the MOCK integration's requestTemplates
                # (keyed on application/json) never matches — the passthrough that follows
                # has no {"statusCode": ...} to read and API Gateway answers 500
                # ("Unable to parse statusCode"), on EVERY leg, auth notwithstanding.
                "params": {"headers": {"Content-Type": "application/json"}},
            }),
            responseMappingTemplate=_RESPONSE_TEMPLATE)
        ctx.on_cleanup(lambda f=field: _ignore_not_found(lambda: svc.delete_resolver(
            apiId=gql_api_id, typeName="Query", fieldName=f)))

    query = "query { openViaUnsigned guardedViaSigned guardedViaUnsigned }"

    # ---- one request carries the whole 2x2 ---------------------------------------------
    # Polls only for the two POSITIVE legs: the IAM role must become assumable by AppSync and
    # the stage servable.
    def _both_positives(res):
        _status, body, _hdrs = res
        data = (body or {}).get("data") or {}
        return (data.get("openViaUnsigned") == marker
                and data.get("guardedViaSigned") == marker)

    status, body, _hdrs = _poll_until(
        lambda: _gql(ctx, gql_url, gql_key, query), _both_positives,
        timeout_s=_ROLE_PROPAGATION_S, interval_s=8.0,
        description=(
            "both positive legs to resolve — the unsigned data source reaching the OPEN "
            "method, and the signed data source being admitted by the AWS_IAM method"
        ),
    )
    assert status == 200, (
        f"the GraphQL request itself must be HTTP 200 even though one field failed; got "
        f"status={status} body={body!r}"
    )
    data = body.get("data")
    assert isinstance(data, dict), f"expected a data object alongside the errors, got {data!r}"

    # positive control A: the UNSIGNED data source can reach this API at all.
    assert data.get("openViaUnsigned") == marker, (
        f"control: the unsigned HTTP data source must reach the authorizationType=NONE method "
        f"and return the origin's marker {marker!r} — without this the 403 below could be an "
        f"unreachable or misconfigured data source rather than IAM enforcement; got "
        f"{data.get('openViaUnsigned')!r}"
    )
    # positive control B: awsIamConfig really signs, and API Gateway really accepts it.
    assert data.get("guardedViaSigned") == marker, (
        f"expected the SIGNED data source (awsIamConfig signingServiceName=execute-api, "
        f"serviceRoleArn with execute-api:Invoke) to be admitted by the AWS_IAM method and "
        f"return {marker!r}; got {data.get('guardedViaSigned')!r} — a null here means AppSync "
        f"did not sign, or signed with the wrong service/region"
    )

    # the claim: the same method refuses the UNSIGNED twin, in this same request.
    assert data.get("guardedViaUnsigned", "MISSING") is None, (
        f"expected the unsigned leg to be present-and-null in data while its siblings "
        f"resolved, got data={data!r} — a marker here means the AWS_IAM method admitted an "
        f"unsigned request, which is an authorization bypass at the origin"
    )
    errors = body.get("errors")
    assert isinstance(errors, list) and len(errors) == 1, (
        f"expected exactly ONE GraphQL error, for the unsigned leg only — more means a "
        f"positive leg also failed, none means the refusal was swallowed; got {errors!r}"
    )
    err = errors[0]
    assert err.get("path") == ["guardedViaUnsigned"], (
        f"expected errors[0].path to name the unsigned field, got {err.get('path')!r} "
        f"(full error {err!r})"
    )
    assert err.get("errorType") == "UpstreamStatusError", (
        f"expected the errorType this check's response template raises, got "
        f"{err.get('errorType')!r} (full error {err!r}) — another errorType means AppSync "
        f"failed before the template ran, so the upstream status was never observed"
    )
    assert err.get("message") == "upstream-status-403", (
        f"expected the response template to render API Gateway's own refusal status into the "
        f"GraphQL error as 'upstream-status-403', got {err.get('message')!r} — the digits come "
        f"from the origin, so this is what attributes the refusal to API Gateway's AWS_IAM "
        f"enforcement rather than to AppSync giving up locally"
    )
    assert marker not in json.dumps(err), (
        f"effect-absent: the refused leg must never carry the origin's body, so the marker "
        f"{marker!r} must not appear anywhere in the error entry; got {err!r}"
    )

    # ---- restore: add the signing config, and the IDENTICAL query resolves --------------
    svc.update_data_source(
        apiId=gql_api_id, name=unsigned_name, type="HTTP", serviceRoleArn=role_arn,
        httpConfig={"endpoint": endpoint, "authorizationConfig": signing})
    updated = svc.get_data_source(apiId=gql_api_id, name=unsigned_name)["dataSource"]
    updated_iam = ((updated.get("httpConfig") or {}).get("authorizationConfig")
                   or {}).get("awsIamConfig") or {}
    assert updated_iam.get("signingServiceName") == "execute-api", (
        f"expected GetDataSource to report the added signing config, got "
        f"httpConfig={updated.get('httpConfig')!r}"
    )

    def _all_three(res):
        _status, rbody, _hdrs = res
        rdata = (rbody or {}).get("data") or {}
        return rdata.get("guardedViaUnsigned") == marker

    _status2, body2, _hdrs2 = _poll_until(
        lambda: _gql(ctx, gql_url, gql_key, query), _all_three,
        timeout_s=_ROLE_PROPAGATION_S, interval_s=8.0,
        description=(
            "the previously refused field to resolve once authorizationConfig was added to "
            "its data source — the restore leg that attributes the 403 to the signing config"
        ),
    )
    data2 = body2.get("data") or {}
    assert data2.get("guardedViaUnsigned") == marker, (
        f"restore: after UpdateDataSource added awsIamConfig, the IDENTICAL query must resolve "
        f"the formerly refused field to {marker!r}; got {data2.get('guardedViaUnsigned')!r}"
    )
    assert not body2.get("errors"), (
        f"restore: with both data sources signing, the identical query must carry NO errors at "
        f"all; got {body2.get('errors')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
