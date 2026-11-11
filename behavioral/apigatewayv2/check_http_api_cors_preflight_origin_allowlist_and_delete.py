"""http-api-cors-preflight-origin-allowlist-and-delete."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-cors-preflight-origin-allowlist-and-delete"
GROUP = 'invoke'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


def _http(method, url, body=None, headers=None):
    """HTTP request via urllib. Returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _poll_http(url, want, method="GET", headers=None, body=None, timeout_s=120):
    """Poll a URL until status == want (absorbing settling noise). Returns (status, body)."""
    status, resp_body = None, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, resp_body = _http(method, url, body=body, headers=headers or {})
        except Exception:
            time.sleep(3)
            continue
        if status == want:
            return status, resp_body
        time.sleep(3)
    return status, resp_body


def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"]


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
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy)
    )

    def _cleanup_role():
        try:
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return arn


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
        "Timeout": 30,
        "MemorySize": 128,
        "Tags": dict(TAGS),
    }
    deadline = time.monotonic() + 40
    last_err = None
    arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            arn = lam.create_function(**kwargs)["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if arn is None:
        raise last_err or RuntimeError(f"failed to create lambda {name}")
    _deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= _deadline:
            raise AssertionError(f"lambda {name} active not met within 60s")
        time.sleep(2.0)
    return {"name": name, "arn": arn}


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _allow_apigw_invoke(ctx, fn_name, api_id):
    lam = ctx.client("lambda")
    src = f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    try:
        lam.add_permission(
            FunctionName=fn_name,
            StatementId="apigw-invoke",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=src,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e) and "already exists" not in str(e).lower():
            raise


def _invoke_url(ctx, api_endpoint, path, stage=None):
    p = path.lstrip("/")
    stg = stage or "$default"
    return f"{ctx.stage_url(api_endpoint, stg)}/{p}"


_ALLOWED_ORIGIN = "https://allowed.example.com"
_DENIED_ORIGIN = "https://evil.example.com"
_MARKER = "v2-cors-backend-ok"

_MARKER_BACKEND_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": "v2-cors-backend-ok"}),
    }
"""

_CORS = {
    "AllowOrigins": [_ALLOWED_ORIGIN],
    "AllowMethods": ["GET"],
    "AllowHeaders": ["content-type"],
    "ExposeHeaders": ["x-app-marker"],
    "MaxAge": 600,
}


def _lower_headers(headers):
    return {k.lower(): v for k, v in (headers or {}).items()}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CorsConfiguration round-trips, is enforced as an origin allowlist on preflight at the
    deployed endpoint, and DeleteCorsConfiguration removes both the config and its effect.
    """
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _MARKER_BACKEND_CODE)
    created = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"),
        ProtocolType="HTTP",
        Tags=TAGS,
        CorsConfiguration=dict(_CORS),
    )
    api_id = created["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    for source, cfg in (("CreateApi", created.get("CorsConfiguration") or {}),
                        ("GetApi", agw.get_api(ApiId=api_id).get("CorsConfiguration") or {})):
        assert cfg.get("AllowOrigins") == [_ALLOWED_ORIGIN], (
            f"{source} AllowOrigins mismatch: {cfg.get('AllowOrigins')}"
        )
        assert cfg.get("AllowMethods") == ["GET"], (
            f"{source} AllowMethods mismatch: {cfg.get('AllowMethods')}"
        )
        assert cfg.get("AllowHeaders") == ["content-type"], (
            f"{source} AllowHeaders mismatch: {cfg.get('AllowHeaders')}"
        )
        assert cfg.get("ExposeHeaders") == ["x-app-marker"], (
            f"{source} ExposeHeaders mismatch: {cfg.get('ExposeHeaders')}"
        )
        assert cfg.get("MaxAge") == 600, f"{source} MaxAge mismatch: {cfg.get('MaxAge')}"

    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /cors", Target=f"integrations/{integ_id}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    _allow_apigw_invoke(ctx, fn["name"], api_id)

    url = _invoke_url(ctx, created["ApiEndpoint"], "/cors", stage="$default")
    status, body = _poll_http(url, 200, headers={"Origin": _ALLOWED_ORIGIN})
    assert status == 200, f"precondition: GET /cors should be 200, got {status}: {body}"
    assert json.loads(body).get("marker") == _MARKER, f"unexpected backend body: {body}"

    preflight = {
        "Origin": _ALLOWED_ORIGIN,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "content-type",
    }
    # No OPTIONS route exists, so API Gateway answers the preflight itself.
    status, headers, body = _http("OPTIONS", url, headers=preflight)
    assert status in (200, 204), f"expected 200/204 for a CORS preflight, got {status}: {body}"
    hdrs = _lower_headers(headers)
    assert hdrs.get("access-control-allow-origin") == _ALLOWED_ORIGIN, (
        f"preflight must echo the allowed origin, got "
        f"{hdrs.get('access-control-allow-origin')!r} (headers={sorted(hdrs)})"
    )
    assert "GET" in (hdrs.get("access-control-allow-methods") or ""), (
        f"preflight access-control-allow-methods must include GET, got "
        f"{hdrs.get('access-control-allow-methods')!r}"
    )
    assert hdrs.get("access-control-max-age") == "600", (
        f"preflight access-control-max-age must be 600, got {hdrs.get('access-control-max-age')!r}"
    )

    denied = dict(preflight, Origin=_DENIED_ORIGIN)
    status, headers, body = _http("OPTIONS", url, headers=denied)
    hdrs = _lower_headers(headers)
    assert "access-control-allow-origin" not in hdrs, (
        f"a non-allowlisted origin must NOT get access-control-allow-origin, got "
        f"{hdrs.get('access-control-allow-origin')!r} (status={status})"
    )

    agw.delete_cors_configuration(ApiId=api_id)
    after = agw.get_api(ApiId=api_id)
    assert not after.get("CorsConfiguration"), (
        f"DeleteCorsConfiguration must clear CorsConfiguration, got {after.get('CorsConfiguration')}"
    )
    deadline = time.monotonic() + 60
    hdrs = {}
    while time.monotonic() < deadline:
        status, headers, body = _http("GET", url, headers={"Origin": _ALLOWED_ORIGIN})
        hdrs = _lower_headers(headers)
        if status == 200 and "access-control-allow-origin" not in hdrs:
            break
        time.sleep(3)
    assert status == 200, f"GET /cors must still serve after DeleteCorsConfiguration, got {status}"
    assert json.loads(body).get("marker") == _MARKER, f"backend body changed: {body}"
    assert "access-control-allow-origin" not in hdrs, (
        f"CORS headers must stop after DeleteCorsConfiguration, still got "
        f"{hdrs.get('access-control-allow-origin')!r}"
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
