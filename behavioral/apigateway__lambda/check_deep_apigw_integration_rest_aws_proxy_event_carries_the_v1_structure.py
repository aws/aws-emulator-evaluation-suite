"""deep-apigw-integration-rest-aws-proxy-event-carries-the-v1-structure."""
from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigw-integration-rest-aws-proxy-event-carries-the-v1-structure"
GROUP = "data-format"
SERVICES = ["apigateway", "lambda"]

_UA = "sim2real-proxy-event-probe/1.0"

# The backend returns the event it RECEIVED, verbatim, so every assertion below is on the
# literal structure API Gateway handed the function — not on anything the function derived.
_ECHO = """
import json


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"event": event}),
    }
"""


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A REST AWS_PROXY integration passes the v1 event: resource beside path, repeated headers and query
    parameters split into multiValue and last-value maps, path and stage variables, and a
    stage-prefixed requestContext.path, without the HTTP API v2 fields."""
    fn = _create_lambda(ctx, _ECHO)
    api_id, root_id = _create_rest_api(ctx, "proxy-v1")
    ag = ctx.client("apigateway")
    items_id = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    item_id = _c(ag.create_resource, restApiId=api_id, parentId=items_id, pathPart="{id}")["id"]
    uri = (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
           f"{fn['arn']}/invocations")
    for method in ("GET", "POST"):
        _c(ag.put_method, restApiId=api_id, resourceId=item_id, httpMethod=method,
           authorizationType="NONE")
        _c(ag.put_integration, restApiId=api_id, resourceId=item_id, httpMethod=method,
           type="AWS_PROXY", integrationHttpMethod="POST", uri=uri)
    account = _account_id(ctx)
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*")
    tier = ctx.unique_name("tier")
    _deploy_stage(ctx, api_id, "live", variables={"tier": tier})

    pid = ctx.unique_name("p")
    url = _rest_invoke_url(ctx, api_id, "live", f"/items/{pid}") + "?a=1&a=2&single=x"
    header_pairs = [("User-Agent", _UA), ("X-Multi", "one"), ("X-Multi", "two"),
                    ("Accept", "application/json")]

    answered = []

    def _probe():
        r = _raw_request("GET", url, header_pairs, verify=ctx.http_verify)
        answered.append(r[0])
        return r

    try:
        status, _h, text = _poll(_probe, lambda r: r[0] == 200, "GET /items/{id} through the proxy")
    except AssertionError as exc:
        if not answered:
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: nothing answered at the deployed stage URL {url}, so the "
                f"AWS_PROXY integration could not be invoked: {exc}"
            ) from exc
        raise
    ev = json.loads(text)["event"]

    assert ev.get("resource") == "/items/{id}", (
        f"`resource` must be the TEMPLATED resource path, got {ev.get('resource')!r}")
    assert ev.get("path") == f"/items/{pid}", (
        f"`path` must be the concrete request path without the stage, got {ev.get('path')!r}")
    assert ev.get("httpMethod") == "GET", f"httpMethod was {ev.get('httpMethod')!r}"
    assert ev.get("pathParameters") == {"id": pid}, (
        f"pathParameters was {ev.get('pathParameters')!r}, expected {{'id': {pid!r}}}")
    assert ev.get("multiValueQueryStringParameters") == {"a": ["1", "2"], "single": ["x"]}, (
        f"a repeated query parameter must arrive as a list in "
        f"multiValueQueryStringParameters, got {ev.get('multiValueQueryStringParameters')!r}")
    assert ev.get("queryStringParameters") == {"a": "2", "single": "x"}, (
        f"queryStringParameters must carry only the LAST value of a repeated parameter, got "
        f"{ev.get('queryStringParameters')!r}")
    mvh = ev.get("multiValueHeaders") or {}
    assert mvh.get("X-Multi") == ["one", "two"], (
        f"a repeated header must arrive as a list in multiValueHeaders, got "
        f"{mvh.get('X-Multi')!r} (all: {sorted(mvh)!r})")
    assert (ev.get("headers") or {}).get("X-Multi") == "two", (
        f"headers must carry only the LAST value of a repeated header, got "
        f"{(ev.get('headers') or {}).get('X-Multi')!r}")
    assert ev.get("stageVariables") == {"tier": tier}, (
        f"stageVariables was {ev.get('stageVariables')!r}, expected {{'tier': {tier!r}}}")
    assert ev.get("isBase64Encoded") is False, (
        f"isBase64Encoded must be False for a text request, got {ev.get('isBase64Encoded')!r}")
    assert ev.get("body") is None, f"a GET with no body must carry body=None, got {ev.get('body')!r}"
    for v2_field in ("rawPath", "rawQueryString", "routeKey", "cookies"):
        assert v2_field not in ev, (
            f"the REST v1 proxy event must not carry the HTTP API v2 field {v2_field!r}; "
            f"event keys were {sorted(ev)!r}")

    rc = ev.get("requestContext") or {}
    assert rc.get("resourcePath") == "/items/{id}", (
        f"requestContext.resourcePath was {rc.get('resourcePath')!r}")
    assert rc.get("httpMethod") == "GET", f"requestContext.httpMethod was {rc.get('httpMethod')!r}"
    assert rc.get("stage") == "live", f"requestContext.stage was {rc.get('stage')!r}"
    assert rc.get("path") == f"/live/items/{pid}", (
        f"requestContext.path must carry the stage prefix, got {rc.get('path')!r}")
    assert rc.get("apiId") == api_id, f"requestContext.apiId was {rc.get('apiId')!r}, expected {api_id!r}"
    assert rc.get("accountId") == account, (
        f"requestContext.accountId was {rc.get('accountId')!r}, expected the caller account")
    assert rc.get("requestId"), f"requestContext.requestId is empty: {rc!r}"
    identity = rc.get("identity") or {}
    try:
        ipaddress.ip_address(identity.get("sourceIp") or "")
    except ValueError as exc:
        raise AssertionError(
            f"requestContext.identity.sourceIp must be the caller's IP address, got "
            f"{identity.get('sourceIp')!r}") from exc
    assert identity.get("userAgent") == _UA, (
        f"requestContext.identity.userAgent was {identity.get('userAgent')!r}, sent {_UA!r}")

    # A POST body reaches the function as the exact string sent, not re-serialized.
    raw_body = '{"b": 1,   "spaced":  "kept"}'
    p_status, _ph, p_text = _raw_request(
        "POST", url, [("Content-Type", "application/json"), ("User-Agent", _UA)],
        body=raw_body.encode(), verify=ctx.http_verify)
    assert p_status == 200, f"POST expected 200, got {p_status}: {p_text[:300]!r}"
    pev = json.loads(p_text)["event"]
    assert pev.get("httpMethod") == "POST", f"POST event httpMethod was {pev.get('httpMethod')!r}"
    assert pev.get("body") == raw_body, (
        f"the proxy event body must be the request body byte-for-byte, got {pev.get('body')!r}")
    assert pev.get("isBase64Encoded") is False, (
        f"a JSON body on an API with no binaryMediaTypes must not be base64'd, got "
        f"{pev.get('isBase64Encoded')!r}")

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_rest_api(ctx, api_id, root_id)
    # A refused connection (the host is not served) also counts as not answering 200.
    _poll(lambda: _raw_request_or_refused("GET", url, header_pairs, verify=ctx.http_verify), lambda r: r[0] != 200,
          "the deleted API's stage URL stops answering 200", timeout_s=_GONE_S)
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, fn["role"], path="/sim2real/")


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx, kind):
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _c(fn, **kw):
    """Call an apigateway control-plane op, retrying only its per-account mutation throttle."""
    for attempt in range(10):
        try:
            return fn(**kw)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or attempt == 9:
                raise
            time.sleep(min(4.0, 0.3 * (2 ** attempt)))
    raise RuntimeError("unreachable")


def _poll(probe, predicate, description, timeout_s=150.0, interval_s=3.0):
    """Poll probe() to a condition (stage/IAM/permission propagation), tolerating
    connection errors while execute-api DNS settles."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = probe()
        except OSError as exc:
            last = ("connection error", {}, repr(exc))
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: condition not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _ssl_context(verify):
    """The TLS context ctx.http_verify asks for: False skips verification, a str is a CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _raw_request(method, url, header_pairs, body=None, verify=True):
    """HTTP via http.client so a header can be sent TWICE (urllib folds duplicates).
    Returns (status, lower-cased headers, text); a 4xx/5xx is a result, not an exception."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        conn = http.client.HTTPSConnection(u.netloc, timeout=25, context=_ssl_context(verify))
    else:
        conn = http.client.HTTPConnection(u.netloc, timeout=25)
    try:
        conn.putrequest(method, u.path + (f"?{u.query}" if u.query else ""),
                        skip_accept_encoding=True)
        for k, v in header_pairs:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        resp = conn.getresponse()
        return (resp.status, {k.lower(): v for k, v in resp.getheaders()},
                resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()


def _raw_request_or_refused(method, url, header_pairs, verify=True):
    """``_raw_request``, with a connection failure reported as status 0 instead of raised."""
    try:
        return _raw_request(method, url, header_pairs, verify=verify)
    except OSError as exc:
        return (0, {}, repr(exc))


def _rest_invoke_url(ctx, api_id, stage, path):
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind, **extra):
    ag = ctx.client("apigateway")
    api_id = _c(ag.create_rest_api, name=_xname(ctx, kind), description=f"sim2real {CHECK}",
                endpointConfiguration={"types": ["REGIONAL"]}, tags=dict(_TAGS), **extra)["id"]
    ctx.on_cleanup(_tolerant(lambda: _c(ag.delete_rest_api, restApiId=api_id), "NotFoundException"))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None):
    ag = ctx.client("apigateway")
    dep_id = _c(ag.create_deployment, restApiId=api_id)["id"]
    kw = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kw["variables"] = variables
    _c(ag.create_stage, **kw)
    ctx.on_cleanup(_tolerant(lambda: _c(ag.delete_stage, restApiId=api_id, stageName=stage),
                            "NotFoundException"))
    return dep_id


def _account_id(ctx):
    return ctx.account


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, name):
    """delete_function does not remove /aws/lambda/<fn>, and a late log flush can recreate it
    after a single delete — so reap in rounds and re-check, declaring a leak if it persists."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    for _ in range(6):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(5)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in found):
            return
    raise AssertionError(f"log group {group} kept reappearing after delete")


def _create_lambda(ctx, handler_code, env=None):
    """Execution role (logs only) + python3.12 function; both teardowns registered at create.
    The log-group reap is registered BEFORE the function so LIFO runs it after the delete."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Path="/sim2real/",
                               Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(_tolerant(lambda: _delete_role(ctx, role_name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*"}]}))
    name = _xname(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kw = {"FunctionName": name, "Runtime": "python3.12", "Role": role_arn,
          "Handler": "lambda_function.lambda_handler", "Code": {"ZipFile": buf.getvalue()},
          "Timeout": 15, "MemorySize": 128, "Tags": dict(_TAGS)}
    if env:
        kw["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(**kw)["FunctionArn"]
            break
        except ClientError as exc:
            # IAM propagation: a brand-new role is not yet assumable by Lambda.
            if (exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException"
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name),
                            "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": name, "arn": arn, "role": role_name}


def _allow_apigw_invoke(ctx, fn_name, source_arn):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com", SourceArn=source_arn)


# ===== teardown proofs (GONE: three beats per family) =====
#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(
    fn, codes: tuple[str, ...], status: int, what: str, names: str | None = None, message: str | None = None
) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, a non-empty message naming ``names``.

    ``message``, where AWS's exact wording is known, must match exactly.
    """
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        if names:
            assert names in msg, f"{what}: {code} message does not name {names!r}: {msg[:200]!r}"
        if message is not None:
            assert msg == message, f"{what}: {code} message {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, names=None, timeout_s: float = _GONE_S, message=None) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, names, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    gone = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", name, message=gone)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}", name)


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", name)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


def _gone_rest_api(ctx, api_id: str, root_id: str) -> None:
    apigw = ctx.client("apigateway")
    _c(apigw.delete_rest_api, restApiId=api_id)
    nf = ("NotFoundException",)
    gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _poll_refused(lambda: apigw.get_rest_api(restApiId=api_id), nf, 404, f"GetRestApi {api_id}", message=gone)
    listed = {a["id"] for a in _paged(apigw, "get_rest_apis", "items")}
    assert api_id not in listed, f"GetRestApis still lists deleted API {api_id}"
    _refused(lambda: _c(apigw.create_resource, restApiId=api_id, parentId=root_id, pathPart="gone"),
             nf, 404, f"CreateResource {api_id}", message=gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
