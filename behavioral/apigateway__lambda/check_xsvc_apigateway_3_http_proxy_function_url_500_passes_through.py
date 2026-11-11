"""xsvc-apigateway-3-http-proxy-function-url-500-passes-through."""
from __future__ import annotations

import io
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-3-http-proxy-function-url-500-passes-through"
GROUP = "error-semantics"
SERVICES = ["apigateway", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """When the Function URL behind an HTTP_PROXY integration answers 500, the API Gateway caller
    receives that 500 unchanged - backend body and header, not a 502 or integration-failure error -
    while a sibling path through the same route is still served 200."""
    secret = secrets.token_urlsafe(32)
    fn = _create_echo_function(ctx, auth_type="NONE", secret=secret)
    api = _create_proxy_api(ctx, fn["host"], fn["scheme"], secret)

    status, headers, body = _await(
        ctx,
        lambda: _http(ctx, api["base"] + "/jobs/fine"),
        lambda r: r[0] == 200 and r[1].get("x-echo-backend") == "fn-url",
        "a GET of a healthy job to be served by the echo backend",
    )
    assert json.loads(body)["path"] == "/jobs/fine", f"control body was {body!r}"

    d_status, _, d_body = _http(ctx, fn["url"].rstrip("/") + "/jobs/boom", headers={"x-sim2real-auth": secret})
    assert d_status == 500, f"function URL answered {d_status!r} {d_body!r} for /jobs/boom directly"
    assert json.loads(d_body)["error"] == "backend-exploded", f"direct 500 body was not the backend's: {d_body!r}"

    status, headers, body = _http(ctx, api["base"] + "/jobs/boom", method="POST", data=b'{"run": true}',
                                  headers={"Content-Type": "application/json"})
    assert status == 500, f"stage returned {status!r} {body!r}; the backend's 500 must pass through"
    assert headers.get("x-echo-backend") == "fn-url", (
        f"backend response header did not pass through with the 500: {headers!r}"
    )
    assert "x-amzn-errortype" not in headers, (
        f"the gateway stamped its own error type on a relayed 500: {headers.get('x-amzn-errortype')!r}"
    )
    echo = json.loads(body)
    assert echo["error"] == "backend-exploded", f"500 body was not the backend's: {body!r}"
    assert echo["method"] == "POST" and echo["path"] == "/jobs/boom", (
        f"500 body echoes {echo['method']!r} {echo['path']!r}, not this request"
    )
    assert json.loads(echo["body"]) == {"run": True}, f"backend saw body {echo['body']!r}"

    # A backend 500 is not sticky: the next request on the same route is served normally.
    status, headers, body = _http(ctx, api["base"] + "/jobs/fine")
    assert status == 200 and json.loads(body)["path"] == "/jobs/fine", (
        f"GET after the relayed 500 returned {status!r} {body!r}"
    )


# ===== helpers =====
_STAGE = "test"
_STREAK = 3

_ECHO_SRC = '''
import base64, hmac, json, os
def handler(event, context):
    seen = dict(event.get("headers") or {})
    token = seen.pop("x-sim2real-auth", "")
    if not hmac.compare_digest(token.encode(), os.environ["SIM2REAL_AUTH"].encode()):
        return {"statusCode": 403, "body": "forbidden"}
    path = event.get("rawPath", "")
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    echo = {"path": path, "rawQueryString": event.get("rawQueryString", ""),
            "headers": seen, "body": body,
            "method": event["requestContext"]["http"]["method"]}
    status = 200
    if path.endswith("/missing"):
        status, echo["error"] = 404, "backend-not-found"
    elif path.endswith("/boom"):
        status, echo["error"] = 500, "backend-exploded"
    return {"statusCode": status,
            "headers": {"content-type": "application/json", "x-echo-backend": "fn-url"},
            "body": json.dumps(echo)}
'''


def _create_echo_function(ctx, auth_type: str, secret: str) -> dict:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-xsvc-agwfn-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # Registered BEFORE the function so LIFO runs it AFTER delete_function. The role carries no
    # logs permission, so no group should ever exist; the loop is the backstop if one does.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", _ECHO_SRC)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn,
                                Handler="index.handler", Code={"ZipFile": buf.getvalue()},
                                Timeout=10, Tags={"sim2real": CHECK},
                                Environment={"Variables": {"SIM2REAL_AUTH": secret}})
            break
        except ClientError as e:
            # A just-created role is not yet assumable by Lambda; nothing to poll but this.
            if e.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    fn_url = lam.create_function_url_config(FunctionName=name, AuthType=auth_type)["FunctionUrl"]
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=name))
    if auth_type == "NONE":
        principal = "*"
    else:
        principal = ctx.client("sts").get_caller_identity()["Account"]
    lam.add_permission(FunctionName=name, StatementId="url-invoke", Action="lambda:InvokeFunctionUrl",
                       Principal=principal, FunctionUrlAuthType=auth_type)
    lam.add_permission(FunctionName=name, StatementId="url-invoke-fn", Action="lambda:InvokeFunction",
                       Principal=principal, InvokedViaFunctionUrl=True)
    parsed = urllib.parse.urlparse(fn_url)
    # A target served over TLS publishes an https function URL; an http target publishes its own scheme.
    schemes = ("https",) if lam.meta.endpoint_url.startswith("https://") else ("http", "https")
    assert parsed.scheme in schemes and parsed.netloc, f"unparseable function URL {fn_url!r}"
    return {"name": name, "url": fn_url, "host": parsed.netloc, "scheme": parsed.scheme}


def _reap_log_group(logs, group: str, window_s: float = 20.0) -> None:
    deadline = time.monotonic() + window_s
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"{group}: {e}") from e
        if time.monotonic() > deadline:
            break
        time.sleep(5)
    found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
    if any(g["logGroupName"] == group for g in found):
        raise RuntimeError(f"{group} reappeared after the reap window")


def _delete_rest_api(apigw, api_id: str, budget_s: float = 120.0) -> None:
    """Delete the REST API, retrying TooManyRequestsException (DeleteRestApi is rate-limited per
    account) every 10 s up to budget_s; NotFoundException counts as deleted, anything else raises."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() > deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from e
            time.sleep(10)


def _create_proxy_api(ctx, backend_host: str, backend_scheme: str, secret: str) -> dict:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-xsvc-agwfn-"),
                                   tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    resources = [r for page in apigw.get_paginator("get_resources").paginate(restApiId=api_id)
                 for r in page["items"]]
    root_id = next(r["id"] for r in resources if r["path"] == "/")
    res_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="{proxy+}")["id"]
    apigw.put_method(restApiId=api_id, resourceId=res_id, httpMethod="ANY", authorizationType="NONE",
                     requestParameters={"method.request.path.proxy": True})
    apigw.put_integration(restApiId=api_id, resourceId=res_id, httpMethod="ANY", type="HTTP_PROXY",
                          integrationHttpMethod="ANY", uri=f"{backend_scheme}://{backend_host}/{{proxy}}",
                          requestParameters={"integration.request.path.proxy": "method.request.path.proxy",
                                             "integration.request.header.x-sim2real-auth": f"'{secret}'"})
    apigw.create_deployment(restApiId=api_id, stageName=_STAGE)
    return {"api_id": api_id, "base": ctx.rest_api_url(api_id, _STAGE)}


def _http(ctx, url: str, method: str = "GET", data: bytes | None = None, headers=None):
    _url, _route = ctx.endpoint_route(url)
    request = urllib.request.Request(_url, method=method, data=data, headers={**(dict(headers or {})), **_route})
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def _await(ctx, probe, pred, what: str, timeout_s: float = 180.0, interval_s: float = 2.0):
    """Poll the live endpoint until `pred` holds for _STREAK consecutive responses."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    streak, last = 0, None
    while time.monotonic() < deadline:
        last = probe()
        streak = streak + 1 if pred(last) else 0
        if streak >= _STREAK:
            return last
        time.sleep(interval_s if streak == 0 else 1.0)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
