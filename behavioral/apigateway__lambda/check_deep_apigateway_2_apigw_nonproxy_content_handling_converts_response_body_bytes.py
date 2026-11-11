"""deep-apigateway-2-apigw-nonproxy-content-handling-converts-response-body-bytes."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import random
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigateway-2-apigw-nonproxy-content-handling-converts-response-body-bytes"
GROUP = "data-format"
SERVICES = ["apigateway", "lambda"]


# ===== helpers =====
# The echo backend: a Lambda behind a function URL that answers 403 unless x-sim2real-auth carries
# the per-run secret the integration sets; it reports the sha256 of the body and the headers and
# query it saw, and /emit-binary and /emit-text answer the `b64` query value as bytes or text.
#
# The execution role has no policy attached, so the function creates no log group.
_ECHO_HANDLER = r'''
import base64, hashlib, hmac, json, os, uuid

def handler(event, context):
    seen = dict(event.get("headers") or {})
    token = seen.pop("x-sim2real-auth", "")
    if not hmac.compare_digest(token.encode(), os.environ["SIM2REAL_AUTH"].encode()):
        return {"statusCode": 403, "body": "forbidden"}
    body = event.get("body") or ""
    raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")
    path = event.get("rawPath") or ""
    query = event.get("queryStringParameters") or {}
    keep = "keep-" + uuid.uuid4().hex
    drop = "drop-" + uuid.uuid4().hex
    headers = {"x-echo-sha256": hashlib.sha256(raw).hexdigest(),
               "x-echo-keep": keep, "x-echo-drop": drop}
    if path.endswith("/emit-binary"):
        headers["content-type"] = "application/octet-stream"
        return {"statusCode": 200, "headers": headers, "isBase64Encoded": True,
                "body": query.get("b64", "")}
    if path.endswith("/emit-text"):
        headers["content-type"] = "text/plain"
        return {"statusCode": 200, "headers": headers, "body": query.get("b64", "")}
    headers["content-type"] = "application/json"
    return {"statusCode": 200, "headers": headers, "body": json.dumps({
        "sha256": hashlib.sha256(raw).hexdigest(), "len": len(raw),
        "headers": seen, "query": query,
        "keep": keep, "drop": drop, "path": path})}
'''

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _retry_throttled(fn, *, attempts=15):
    """Call fn(), retrying only TooManyRequestsException with jittered, capped backoff.

    The API Gateway control plane rate-limits mutating calls per account (DeleteRestApi is one
    per 30 s), so a throttle here says nothing about the behavior under test."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(8.0, 0.25 * (2 ** attempt)) + random.uniform(0, 0.5))


def _http(ctx, method, url, body=None, headers=None):
    """One raw HTTP request; returns (status, lowercased headers, body BYTES)."""
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, data=body, method=method, headers={**(headers or {}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - https only
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read()


def _poll_http(ctx, url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=180.0, interval_s=3.0, description="endpoint response"):
    """Re-issue a request until predicate(status, headers, body) holds, with a deadline.

    A new function URL and a fresh stage deployment both become servable asynchronously, so the
    first touch polls to an observable condition instead of sleeping."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, data = _http(ctx, method, url, body=body, headers=headers)
        if predicate(status, resp_headers, data):
            return status, resp_headers, data
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {data[:300]!r})")
        time.sleep(interval_s)


def _echo_backend(ctx):
    """Create the echo Lambda + public function URL (every create paired with its teardown)
    and return (URL with no trailing slash, the caller secret it requires), once it answers."""
    secret = secrets.token_urlsafe(32)
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-xsvc-nonproxy-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_TRUST,
        Description=f"sim2real {CHECK} echo backend (no policies)",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _ECHO_HANDLER)
    fn = ctx.unique_name("sim2real-xsvc-nonproxy-")
    # IAM propagation exposes no condition to poll: the bounded retry on the one error a
    # not-yet-assumable role produces IS the wait.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, MemorySize=128,
                Description=f"sim2real {CHECK} echo backend", Tags={"sim2real": CHECK},
                Environment={"Variables": {"SIM2REAL_AUTH": secret}},
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")
                    and time.monotonic() < deadline):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    url = lam.create_function_url_config(FunctionName=fn, AuthType="NONE")["FunctionUrl"]
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=fn))
    lam.add_permission(FunctionName=fn, StatementId="sim2real-url",
                       Action="lambda:InvokeFunctionUrl", Principal="*",
                       FunctionUrlAuthType="NONE")
    lam.add_permission(FunctionName=fn, StatementId="sim2real-url-invoke",
                       Action="lambda:InvokeFunction", Principal="*",
                       InvokedViaFunctionUrl=True)
    url = url.rstrip("/")
    _poll_http(ctx, url + "/echo", lambda s, h, b: s == 200,
               headers={"x-sim2real-auth": secret},
               description=f"the echo function URL {url}/echo answering 200")
    return url, secret


def _create_api(ctx, ag, *, binary_media_types=None):
    """A REGIONAL REST API (registered for teardown). Its only handle is a server-minted id, so
    name, description AND tag all carry the sim2real marker to identify a leftover."""
    kwargs = {"binaryMediaTypes": binary_media_types} if binary_media_types else {}
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-nonproxy-"), description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK}, **kwargs,
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ag, api_id, path_part):
    """A child resource off root; it dies with the API, whose teardown is registered."""
    root = next(i["id"] for i in ag.get_resources(restApiId=api_id)["items"] if i["path"] == "/")
    return _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=root, pathPart=path_part))["id"]


def _http_method(ag, secret, api_id, resource_id, http_method, *, integration, method_params=None,
                 integration_response=None, response_headers=()):
    """A non-proxy HTTP integration with one 200 method response / integration response; it
    sends the echo's caller secret as the static x-sim2real-auth header."""
    integration = {**integration, "requestParameters": {
        **integration.get("requestParameters", {}),
        "integration.request.header.x-sim2real-auth": f"'{secret}'"}}
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE", requestParameters=method_params or {}))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="HTTP",
        **integration))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        responseParameters={f"method.response.header.{h}": False for h in response_headers}))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        selectionPattern="", **(integration_response or {})))


def _deploy(ctx, ag, api_id):
    """Deploy to a stage and return the stage's base invoke URL (no trailing slash): the real
    execute-api vhost, or the emulator's /_aws/execute-api/<id>/<stage>/ route."""
    stage = "live"
    _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName=stage))
    return ctx.rest_api_url(api_id, stage)


def _sha(data):
    return hashlib.sha256(data).hexdigest()
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Response contentHandling converts the backend body before the client sees it, whatever the
    Accept header (TO_BINARY decodes base64 text, TO_TEXT encodes raw binary), while an unset twin
    follows the documented Accept-driven passthrough rule."""
    ag = ctx.client("apigateway")
    echo, secret = _echo_backend(ctx)
    api_id = _create_api(ctx, ag, binary_media_types=["application/octet-stream"])
    variants = {"tobin": ("emit-text", "CONVERT_TO_BINARY"), "tobin-unset": ("emit-text", None),
                "totext": ("emit-binary", "CONVERT_TO_TEXT"), "totext-unset": ("emit-binary", None)}
    for path, (backend_path, handling) in variants.items():
        _http_method(
            ag, secret, api_id, _child(ag, api_id, path), "GET",
            method_params={"method.request.querystring.b64": False},
            integration={
                "integrationHttpMethod": "GET", "uri": f"{echo}/{backend_path}",
                "requestParameters": {
                    "integration.request.querystring.b64": "method.request.querystring.b64"},
            },
            integration_response={"contentHandling": handling} if handling else {},
        )
    base = _deploy(ctx, ag, api_id)

    raw = bytes(range(256)) + os.urandom(64)
    b64 = base64.b64encode(raw)
    query = "?b64=" + urllib.parse.quote(b64.decode(), safe="")
    as_text = {"Accept": "text/plain"}
    as_binary = {"Accept": "application/octet-stream"}

    def client_got(path, headers):
        status, _h, data = _http(ctx, "GET", f"{base}/{path}{query}", headers=headers)
        assert status == 200, f"GET /{path} returned {status!r}: {data[:300]!r}"
        return data

    _poll_http(ctx, f"{base}/tobin-unset{query}", lambda s, h, b: s == 200, headers=as_text,
               description="the deployed stage serving GET /tobin-unset")

    # Backend answers base64 TEXT; Accept: text/plain, under which the unset twin keeps text.
    got = client_got("tobin", as_text)
    assert _sha(got) == _sha(raw), (
        f"CONVERT_TO_BINARY must decode the backend's base64 text into the {len(raw)} raw bytes "
        f"({_sha(raw)}); the client got {len(got)} bytes ({_sha(got)}): {got[:40]!r}")
    got = client_got("tobin-unset", as_text)
    assert got == b64, (
        f"the unset twin must hand the client the backend's base64 text untouched "
        f"({len(b64)} bytes, {_sha(b64)}); got {len(got)} bytes ({_sha(got)})")

    # Backend answers raw BINARY; Accept: application/octet-stream, under which the unset twin
    # keeps binary.
    got = client_got("totext", as_binary)
    assert got == b64, (
        f"CONVERT_TO_TEXT must encode the backend's binary answer as base64 text "
        f"({len(b64)} bytes, {_sha(b64)}); the client got {len(got)} bytes ({_sha(got)})")
    got = client_got("totext-unset", as_binary)
    assert _sha(got) == _sha(raw), (
        f"the unset twin must hand the client the backend's raw bytes untouched ({_sha(raw)}); "
        f"got {len(got)} bytes ({_sha(got)}): {got[:40]!r}")

    # Flip Accept: an explicit contentHandling is unmoved, the unset twins follow Accept.
    got = client_got("tobin", as_binary)
    assert _sha(got) == _sha(raw), (
        f"CONVERT_TO_BINARY must not depend on Accept; with Accept: application/octet-stream the "
        f"client got {_sha(got)}, expected the raw bytes {_sha(raw)}")
    got = client_got("totext", as_text)
    assert got == b64, (
        f"CONVERT_TO_TEXT must not depend on Accept; with Accept: text/plain the client got "
        f"{len(got)} bytes ({_sha(got)}), expected the base64 text {_sha(b64)}")
    got = client_got("tobin-unset", as_binary)
    assert _sha(got) == _sha(raw), (
        f"an unset integration response must decode a text body to binary when Accept names a "
        f"binaryMediaType; got {len(got)} bytes ({_sha(got)}), expected {_sha(raw)}")
    got = client_got("totext-unset", as_text)
    assert got == b64, (
        f"an unset integration response must encode a binary body as base64 text when Accept "
        f"names no binaryMediaType; got {len(got)} bytes ({_sha(got)}), expected {_sha(b64)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
