"""xsvc-apigateway-3-http-proxy-iam-function-url-unsigned-forward-forbidden."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-3-http-proxy-iam-function-url-unsigned-forward-forbidden"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "lambda"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP_PROXY integration forwards the request unsigned, so a REST API in front of an
    AWS_IAM Lambda Function URL relays the function's 403 and the function never runs - while a
    SigV4-signed request straight to the same URL is served 200.
    """
    fn = _create_echo_function(ctx, auth_type="AWS_IAM")
    api = _create_proxy_api(ctx, fn["host"], fn["scheme"])
    signer_creds = ctx.client("lambda")._request_signer._credentials.get_frozen_credentials()

    def _signed_direct():
        url = fn["url"].rstrip("/") + "/direct/ok?via=sigv4"
        req = AWSRequest(method="GET", url=url)
        SigV4Auth(signer_creds, "lambda", ctx.region).add_auth(req)
        return _http(ctx, url, headers=dict(req.headers))

    # Positive control: signed, straight to the function URL -> the function runs.
    status, headers, body = _await(
        _signed_direct,
        lambda r: r[0] == 200 and r[1].get("x-echo-backend") == "fn-url",
        "a SigV4-signed GET to the AWS_IAM function URL to be served",
    )
    echo = json.loads(body)
    assert echo["path"] == "/direct/ok" and echo["rawQueryString"] == "via=sigv4", (
        f"signed direct call echoed {body!r}"
    )

    # The one broken thing: the hop the gateway makes carries no signature.
    status, headers, body = _http(ctx, api["base"] + "/items/abc?via=gateway")
    assert status == 403, f"stage returned {status!r} {body!r}; expected the function URL's 403"
    assert headers.get("x-echo-backend") is None, (
        f"the function ran on an unsigned proxied request: {headers!r} {body!r}"
    )
    assert json.loads(body) == {"Message": "Forbidden"}, f"proxied refusal body was {body!r}"
    assert "via=gateway" not in body, f"refusal body contains the echoed request: {body!r}"

    # And the refusal is the function URL's, not the stage's: the same unsigned request sent
    # straight to the function URL is refused identically.
    d_status, _, d_body = _http(ctx, fn["url"].rstrip("/") + "/items/abc?via=direct")
    assert d_status == 403 and json.loads(d_body) == {"Message": "Forbidden"}, (
        f"unsigned direct call to the AWS_IAM function URL got {d_status!r} {d_body!r}"
    )

    # The function is still healthy after both refusals.
    status, headers, body = _signed_direct()
    assert status == 200 and headers.get("x-echo-backend") == "fn-url", (
        f"signed direct call after the refusals got {status!r} {body!r}"
    )


# ===== helpers =====
_STAGE = "test"
_STREAK = 3

_ECHO_SRC = '''
import base64, json
def handler(event, context):
    path = event.get("rawPath", "")
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    echo = {"path": path, "rawQueryString": event.get("rawQueryString", ""),
            "headers": event.get("headers") or {}, "body": body,
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


def _create_echo_function(ctx, auth_type: str) -> dict:
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
                                Timeout=10, Tags={"sim2real": CHECK})
            break
        except ClientError as e:
            # A just-created role is not yet assumable by Lambda; nothing to poll but this.
            if e.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 90}
    )

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


def _create_proxy_api(ctx, backend_host: str, backend_scheme: str) -> dict:
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
                          requestParameters={"integration.request.path.proxy": "method.request.path.proxy"})
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


def _await(probe, pred, what: str, timeout_s: float = 180.0, interval_s: float = 3.0):
    """Poll the live endpoint until `pred` holds for _STREAK consecutive responses."""
    deadline = time.monotonic() + timeout_s
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
