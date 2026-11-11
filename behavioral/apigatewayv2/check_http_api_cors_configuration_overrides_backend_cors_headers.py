"""http-api-cors-configuration-overrides-backend-cors-headers."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-cors-configuration-overrides-backend-cors-headers"
GROUP = 'cors'
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
    """Poll a URL until status == want (absorbing DNS/auto-deploy settling). Returns (status, headers, body)."""
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
    return status, {k.lower(): v for k, v in resp_headers.items()}, resp_body


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


_ALLOWED = "https://ok.example.com"
_FOREIGN = "https://elsewhere.example.net"
_BACKEND_ORIGIN = "https://backend-chosen.example.org"

# The backend sets its OWN CORS headers; API Gateway must replace them with the API's.
_CORS_BACKEND_CODE = """
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/plain",
            "Access-Control-Allow-Origin": "%s",
            "Access-Control-Expose-Headers": "x-backend-only",
            "X-Marker": "backend-served",
        },
        "body": "backend-served",
    }
""" % _BACKEND_ORIGIN


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With CorsConfiguration set, the backend's own Access-Control-* headers are replaced by the
    API's for an allowed origin and dropped for a foreign one, while the response is still served.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-cors.html
    """
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _CORS_BACKEND_CODE)
    api_id, api_endpoint = _create_http_api(
        ctx,
        CorsConfiguration={
            "AllowOrigins": [_ALLOWED],
            "AllowMethods": ["GET"],
            "ExposeHeaders": ["x-marker"],
        },
    )
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /r", Target=f"integrations/{integ_id}")
    _allow_apigw_invoke(ctx, fn["name"], api_id)
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    url = _url(ctx, api_endpoint, "$default", "/r")

    status, hdrs, body = _poll_http(url, 200, headers={"Origin": _ALLOWED})
    assert status == 200 and body == "backend-served", (
        f"allowed origin: expected 200 + backend body, got {status}: {body[:300]!r}"
    )
    assert hdrs.get("access-control-allow-origin") == _ALLOWED, (
        f"allowed origin: access-control-allow-origin must be the API's {_ALLOWED!r}, got "
        f"{hdrs.get('access-control-allow-origin')!r}"
    )
    assert hdrs.get("access-control-expose-headers") == "x-marker", (
        f"allowed origin: access-control-expose-headers must be the API's 'x-marker', got "
        f"{hdrs.get('access-control-expose-headers')!r}"
    )
    assert hdrs.get("x-marker") == "backend-served", (
        f"non-CORS backend headers must still pass through, got x-marker={hdrs.get('x-marker')!r}"
    )

    status, hdrs, body = _http("GET", url, headers={"Origin": _FOREIGN})
    hdrs = {k.lower(): v for k, v in hdrs.items()}
    assert status == 200 and body == "backend-served", (
        f"foreign origin: the response is still delivered; expected 200 + backend body, got "
        f"{status}: {body[:300]!r}"
    )
    assert "access-control-allow-origin" not in hdrs, (
        f"foreign origin: no access-control-allow-origin may be returned (the backend's must not "
        f"leak through), got {hdrs.get('access-control-allow-origin')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
