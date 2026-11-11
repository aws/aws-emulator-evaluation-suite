"""java-apigw-proxy-request-fields-and-response-shaping-round-trip."""
from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-apigw-proxy-request-fields-and-response-shaping-round-trip"
GROUP = "data-format"
SERVICES = ["apigateway", "lambda"]

# com.amazonaws.services.lambda.runtime.RequestHandler<Map<String,Object>, Map<String,Object>>:
# the AWS_PROXY request reaches the handler as a generic Map (no APIGatewayProxyRequestEvent
# POJO), and the handler builds its own response Map honouring statusCode/headers/body and the
# isBase64Encoded flag, for both a JSON reply and a binary one. Compiled once under JDK 8 (class
# file major version 52).
_SHA256 = "bbc30dbe346887b4d807c5e18944b6d51a36173acf61cccecac7348255619248"

_B64 = (  # @@GENERATED@@ probe/ApiGwProxyHandler.class
    "yv66vgAAADQAeAoAKQA8CAA9CwAHAD4HAD8IAEAIAEEHAEIIAEMIAEQHAEUKAAoAPAgARgoABABHCABICgBJAEoLAAcASwgA"
    "TAgATQgATggATwkAUABRCABSCABTCABUCABVBwBWCgAaADwIAFcKABoAWAgAWQgAWggAWwgAXAgAXQoAGgBeCABfCABgCQBQ"
    "AGEKACgAYgcAYwcAZAcAZQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAA1oYW5kbGVSZXF1ZXN0"
    "AQBPKExqYXZhL3V0aWwvTWFwO0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZh"
    "L3V0aWwvTWFwOwEADVN0YWNrTWFwVGFibGUHAGMHAEIHAGYHAD8BAAlTaWduYXR1cmUBAJsoTGphdmEvdXRpbC9NYXA8TGph"
    "dmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGlt"
    "ZS9Db250ZXh0OylMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEAVShMamF2"
    "YS9sYW5nL09iamVjdDtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OylMamF2YS9sYW5n"
    "L09iamVjdDsBALRMamF2YS9sYW5nL09iamVjdDtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9SZXF1"
    "ZXN0SGFuZGxlcjxMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+O0xqYXZhL3V0"
    "aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47PjsBAApTb3VyY2VGaWxlAQAWQXBpR3dQcm94"
    "eUhhbmRsZXIuamF2YQwAKwAsAQAKaHR0cE1ldGhvZAwAZwBoAQAQamF2YS9sYW5nL1N0cmluZwEABHBhdGgBABVxdWVyeVN0"
    "cmluZ1BhcmFtZXRlcnMBAA1qYXZhL3V0aWwvTWFwAQAHaGVhZGVycwEABG1vZGUBABFqYXZhL3V0aWwvSGFzaE1hcAEABmJp"
    "bmFyeQwAaQBqAQAKc3RhdHVzQ29kZQcAawwAbABtDABuAG8BAAxDb250ZW50LVR5cGUBABhhcHBsaWNhdGlvbi9vY3RldC1z"
    "dHJlYW0BAAtYLUVjaG8tTW9kZQEAD2lzQmFzZTY0RW5jb2RlZAcAcAwAcQByAQAEYm9keQEAGFNtRjJZUzF3Y205NGVTMWlh"
    "VzVoY25rPQEAAXgBAA5YLVByb2JlLUhlYWRlcgEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQALeyJtZXRob2QiOiIMAHMA"
    "dAEACiIsInBhdGgiOiIBAAciLCJ4IjoiAQAMIiwiaGVhZGVyIjoiAQAKIiwiYm9keSI6IgEAAiJ9DAB1AHYBABBhcHBsaWNh"
    "dGlvbi9qc29uAQANWC1FY2hvLU1ldGhvZAwAdwByDAAvADABABdwcm9iZS9BcGlHd1Byb3h5SGFuZGxlcgEAEGphdmEvbGFu"
    "Zy9PYmplY3QBADRjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5kbGVyAQAtY29tL2Ft"
    "YXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0AQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2"
    "YS9sYW5nL09iamVjdDsBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBABFqYXZhL2xhbmcvSW50ZWdlcgEAB3Zh"
    "bHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7AQADcHV0AQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2Jq"
    "ZWN0OylMamF2YS9sYW5nL09iamVjdDsBABFqYXZhL2xhbmcvQm9vbGVhbgEABFRSVUUBABNMamF2YS9sYW5nL0Jvb2xlYW47"
    "AQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAIdG9TdHJpbmcBABQo"
    "KUxqYXZhL2xhbmcvU3RyaW5nOwEABUZBTFNFACEAKAApAAEAKgAAAAMAAQArACwAAQAtAAAAHQABAAEAAAAFKrcAAbEAAAAB"
    "AC4AAAAGAAEAAAAHAAEALwAwAAIALQAAAkEAAwAOAAABgisSArkAAwIAwAAETisSBbkAAwIAwAAEOgQrEga5AAMCAMAABzoF"
    "KxIIuQADAgDAAAc6BhkFxwAHAacADxkFEgm5AAMCAMAABDoHuwAKWbcACzoIuwAKWbcACzoJEgwZB7YADZkAUxkIEg4RAMm4"
    "AA+5ABADAFcZCRIREhK5ABADAFcZCRITEgy5ABADAFcZCBIIGQm5ABADAFcZCBIUsgAVuQAQAwBXGQgSFhIXuQAQAwBXGQiw"
    "GQXHAAcBpwAPGQUSGLkAAwIAwAAEOgoZBscABwGnAA8ZBhIZuQADAgDAAAQ6CysSFrkAAwIAwAAEOgy7ABpZtwAbEhy2AB0t"
    "tgAdEh62AB0ZBLYAHRIftgAdGQq2AB0SILYAHRkLtgAdEiG2AB0ZDLYAHRIitgAdtgAjOg0ZCBIOEQDIuAAPuQAQAwBXGQkS"
    "ERIkuQAQAwBXGQkSJS25ABADAFcZCBIIGQm5ABADAFcZCBIUsgAmuQAQAwBXGQgSFhkNuQAQAwBXGQiwAAAAAgAuAAAAagAa"
    "AAAACgAMAAsAGQAMACYADQAzAA4ASgAPAFMAEABcABEAZgASAHYAEwCCABQAjgAVAJoAFgCnABcAswAYALYAGgDNABsA5AAc"
    "APEAHQEzAB8BQwAgAU8AIQFaACIBZgAjAXMAJAF/ACUAMQAAAD0AB/8APAAHBwAyBwAzBwA0BwA1BwA1BwAzBwAzAABLBwA1"
    "/gBtBwA1BwAzBwAzCEsHADX8AAoHADVLBwA1ADYAAAACADcQQQAvADgAAQAtAAAAIgADAAMAAAAKKivAAAcstgAnsAAAAAEA"
    "LgAAAAYAAQAAAAcAAgA2AAAAAgA5ADoAAAACADs="
)

_EXPECTED_BINARY_BYTES = b"Java-proxy-binary"


def _deployment_zip() -> bytes:
    raw = base64.b64decode(_B64)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256, f"embedded class is sha256 {got!r}, pinned {_SHA256!r}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/ApiGwProxyHandler.class", raw)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _reap_log_group(ctx, logs, name: str, *, reads: int = 3, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"reaping log group {name}: the run budget ended first; not graded")
                raise AssertionError(f"log group {name} still present after its reap budget")
            time.sleep(interval_s)


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = probe()
        except OSError as exc:
            last = ("connection error", repr(exc))
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)


def _execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-javaagw-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy),
                             "NoSuchEntity"))
    return arn


def _create(ctx, lam, kwargs, cap_s=120):
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed by Lambda" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        f"CreateFunction role propagation: the run budget ended first; not graded"
                    )
                raise
            time.sleep(3.0)


def _wait_active(ctx, lam, fn, cap_s=300):
    return _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] == "Active", timeout_s=_budget_s(ctx, cap_s), interval_s=2.0,
        description=f"{fn} reaching State=Active")


def _function(ctx, lam, logs, **kwargs):
    fn = kwargs["FunctionName"]
    _create(ctx, lam, kwargs)
    ctx.on_cleanup(lambda: _reap_log_group(ctx, logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    arn = _wait_active(ctx, lam, fn)["FunctionArn"]
    return fn, arn


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _raw_request(url, *, headers=None, verify=True):
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=25,
                                           context=_ssl_context(verify))
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=25)
    try:
        conn.request("GET", u.path + (f"?{u.query}" if u.query else ""), headers=headers or {})
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A REST API AWS_PROXY integration to a Java RequestHandler<Map,Map>: the handler reads
    httpMethod, path, queryStringParameters and headers from the generic request Map, and its
    response Map shapes the HTTP reply through statusCode, headers, body and isBase64Encoded.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    iam_role = _execution_role(ctx)
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn_name = ctx.unique_name("sim2real-behav-javaagw-fn-")
    fn_name, fn_arn = _function(
        ctx, lam, logs, FunctionName=fn_name, Runtime="java11.al2023",
        Handler="probe.ApiGwProxyHandler", Role=iam_role, Code={"ZipFile": _deployment_zip()},
        MemorySize=512, Timeout=20, Tags={"sim2real": CHECK})

    ag = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-behav-javaagw-api-")
    api_id = ag.create_rest_api(name=api_name, endpointConfiguration={"types": ["REGIONAL"]},
                                binaryMediaTypes=["*/*"],
                                tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    echo_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="echo")["id"]
    ag.put_method(restApiId=api_id, resourceId=echo_id, httpMethod="GET", authorizationType="NONE")
    uri = (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
           f"{fn_arn}/invocations")
    ag.put_integration(restApiId=api_id, resourceId=echo_id, httpMethod="GET",
                       type="AWS_PROXY", integrationHttpMethod="POST", uri=uri)

    lam.add_permission(FunctionName=fn_name, StatementId="apigw-invoke",
                       Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
                       SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*")

    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName="live", deploymentId=dep_id)
    ctx.on_cleanup(_teardown(lambda: ag.delete_stage(restApiId=api_id, stageName="live"),
                             "NotFoundException"))

    base_url = f"{ctx.rest_api_url(api_id, 'live')}/echo"

    _, headers, body = _poll_until(
        ctx,
        lambda: _raw_request(f"{base_url}?x=hello123",
                             headers={"X-Probe-Header": "world456"}, verify=ctx.http_verify),
        lambda r: r[0] == 200,
        timeout_s=_budget_s(ctx, 150.0), interval_s=3.0, description=f"GET {base_url}?x=hello123")
    assert headers.get("content-type") == "application/json", f"headers: {headers!r}"
    assert headers.get("x-echo-method") == "GET", f"headers: {headers!r}"
    echoed = json.loads(body.decode())
    assert echoed == {"method": "GET", "path": "/echo", "x": "hello123",
                      "header": "world456", "body": "null"}, (
        f"the Java handler's echoed request fields were {echoed!r}")

    status2, headers2, body2 = _raw_request(f"{base_url}?mode=binary",
                                            headers={"Accept": "application/octet-stream"},
                                            verify=ctx.http_verify)
    assert status2 == 201, f"expected 201 for mode=binary, got {status2}: {body2[:300]!r}"
    assert headers2.get("content-type") == "application/octet-stream", f"headers: {headers2!r}"
    assert headers2.get("x-echo-mode") == "binary", f"headers: {headers2!r}"
    assert body2 == _EXPECTED_BINARY_BYTES, (
        f"isBase64Encoded=true must decode to the handler's raw bytes; API Gateway delivered "
        f"{body2!r}, expected {_EXPECTED_BINARY_BYTES!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
