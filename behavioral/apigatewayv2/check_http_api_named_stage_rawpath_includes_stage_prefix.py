"""http-api-named-stage-rawpath-includes-stage-prefix."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-named-stage-rawpath-includes-stage-prefix"
GROUP = 'invoke'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

_EVENT_ECHO_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(event),
    }
"""


def _http(method, url, body=None, headers=None):
    """HTTP request via urllib; returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _poll_http(url, want, method="GET", headers=None, body=None, timeout_s=120):
    """Poll a URL until status == want (absorbing DNS/auto-deploy settling)."""
    status, resp_headers, resp_body = None, {}, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, resp_headers, resp_body = _http(method, url, body=body, headers=headers or {})
        except Exception:  # noqa: BLE001 - DNS/connect warm-up, retried within the budget
            time.sleep(3)
            continue
        if status == want:
            break
        time.sleep(3)
    return status, resp_headers, resp_body


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=TAGS_KV,
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return arn


def _delete_lambda_log_group(ctx, function_name):
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_lambda(ctx, handler_code):
    """Create a python Lambda; return {name, arn}. Registers teardown."""
    role_arn = _create_lambda_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 10,
        "MemorySize": 128,
        "Tags": dict(TAGS),
    }
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, name))
    deadline = time.monotonic() + 60
    arn = None
    while arn is None:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
        except ClientError as e:
            # IAM propagation: a freshly created role is not yet assumable by Lambda.
            if "cannot be assumed" in str(e) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"lambda {name} did not become Active within 60s (last {state!r})")
        time.sleep(2.0)
    return {"name": name, "arn": arn}


def _allow_apigw_invoke(ctx, fn_name, api_id):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )


def _create_http_api(ctx, **extra):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS, **extra
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"], api["ApiEndpoint"]


def _url(ctx, api_endpoint, stage, path):
    return f"{ctx.stage_url(api_endpoint, stage)}/{path.lstrip('/')}"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """On a named stage the backend's rawPath includes the stage prefix but route matching does not;
    on the $default stage the prefix is absent, and unmatched paths fall to the $default route.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _EVENT_ECHO_CODE)
    api_id, api_endpoint = _create_http_api(ctx)
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for rk in ("GET /items", "$default"):
        agw.create_route(ApiId=api_id, RouteKey=rk, Target=f"integrations/{integ_id}")
    _allow_apigw_invoke(ctx, fn["name"], api_id)
    for stage in ("$default", "dev"):
        agw.create_stage(ApiId=api_id, StageName=stage, AutoDeploy=True, Tags=TAGS)
        ctx.on_cleanup(lambda s=stage: agw.delete_stage(ApiId=api_id, StageName=s))

    status, _, body = _poll_http(_url(ctx, api_endpoint, "dev", "/items"), 200)
    assert status == 200, f"GET /dev/items expected 200, got {status}: {body[:300]!r}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "GET /items", (
        f"the stage prefix must not take part in route matching; routeKey was {ev.get('routeKey')!r}"
    )
    assert ev.get("rawPath") == "/dev/items", (
        f"on a named stage rawPath carries the stage prefix; expected '/dev/items', "
        f"got {ev.get('rawPath')!r}"
    )
    rc = ev.get("requestContext") or {}
    assert rc.get("stage") == "dev", f"requestContext.stage expected 'dev', got {rc.get('stage')!r}"
    assert (rc.get("http") or {}).get("path") == "/dev/items", (
        f"requestContext.http.path expected '/dev/items', got {(rc.get('http') or {}).get('path')!r}"
    )

    status, _, body = _poll_http(_url(ctx, api_endpoint, "$default", "/items"), 200)
    assert status == 200, f"GET /items on $default expected 200, got {status}: {body[:300]!r}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "GET /items", f"routeKey on $default was {ev.get('routeKey')!r}"
    assert ev.get("rawPath") == "/items", (
        f"the $default stage adds no prefix; expected rawPath '/items', got {ev.get('rawPath')!r}"
    )
    assert (ev.get("requestContext") or {}).get("stage") == "$default", (
        f"requestContext.stage expected '$default', got {(ev.get('requestContext') or {}).get('stage')!r}"
    )

    status, _, body = _poll_http(_url(ctx, api_endpoint, "dev", "/other/x"), 200)
    assert status == 200, f"GET /dev/other/x expected 200 via the $default route, got {status}: {body[:300]!r}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "$default", (
        f"an unmatched path on a named stage falls through to the $default route; routeKey was "
        f"{ev.get('routeKey')!r}"
    )
    assert ev.get("rawPath") == "/dev/other/x", (
        f"expected rawPath '/dev/other/x' on the fallthrough, got {ev.get('rawPath')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
