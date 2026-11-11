"""http-api-path-without-stage-prefix-not-delivered."""
from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-path-without-stage-prefix-not-delivered"
GROUP = 'invoke'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# The backend lives on the target: a Lambda proxy integration echoing what API Gateway routed.
_ROUTE_ECHO_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"routeKey": event.get("routeKey"), "rawPath": event.get("rawPath")}),
    }
"""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is the response under test: hand it back as-is, never follow it."""

    def redirect_request(self, *args, **kwargs):
        return None


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method, url, headers=None):
    """One request, redirects not followed. Returns (status, lower-cased headers, body_str)."""
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_ssl_context(ctx))
    )
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _delete_lambda_log_group(ctx, function_name):
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_backend(ctx, api_id):
    """A python Lambda echoing the routed request, invokable by this API; returns its ARN."""
    role_arn = _create_lambda_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _ROUTE_ECHO_CODE)
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
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
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
            raise AssertionError(f"lambda did not become Active within 60s (last {state!r})")
        time.sleep(2.0)
    lam.add_permission(
        FunctionName=name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )
    return arn


def _poll_http(ctx, url, want, timeout_s=120):
    """Poll a URL until status == want (absorbing DNS/auto-deploy settling). Returns (status, body)."""
    status, body = None, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http(ctx, "GET", url)
        except Exception:  # noqa: BLE001 - DNS/connect warm-up, retried within the budget
            time.sleep(3)
            continue
        if status == want:
            break
        time.sleep(3)
    return status, body


def _routed(body):
    """The routeKey the backend echoed, or None when the body is not the backend's echo."""
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    return doc.get("routeKey") if isinstance(doc, dict) else None


def _url(ctx, api_endpoint, stage, path):
    return f"{ctx.stage_url(api_endpoint, stage)}/{path.lstrip('/')}"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP API whose only stage is a named stage serves nothing at the bare host: a request without the
    stage prefix, or under an undeclared stage, gets API Gateway's 404 and never reaches the backend,
    while the named stage keeps serving."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    fn_arn = _create_backend(ctx, api_id)
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn_arn,
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /ip", Target=f"integrations/{integ_id}")
    agw.create_stage(ApiId=api_id, StageName="prod", AutoDeploy=True, Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="prod"))
    stages = sorted(s["StageName"] for s in agw.get_stages(ApiId=api_id)["Items"])
    assert stages == ["prod"], f"the API must have exactly the 'prod' stage, got {stages!r}"

    control = _url(ctx, api_endpoint, "prod", "/ip")
    status, body = _poll_http(ctx, control, 200)
    assert status == 200, f"control GET /prod/ip expected 200, got {status}: {body[:300]!r}"
    assert _routed(body) == "GET /ip", (
        f"control must carry the backend body naming 'GET /ip', got {body[:200]!r}"
    )

    for label, url in (
        ("bare host (no stage prefix)", _url(ctx, api_endpoint, "$default", "/ip")),
        ("undeclared stage 'qa'", _url(ctx, api_endpoint, "qa", "/ip")),
    ):
        status, _, body = _http(ctx, "GET", url)
        assert status == 404, f"{label}: expected 404, got {status}: {body[:300]!r}"
        assert json.loads(body) == {"message": "Not Found"}, (
            f"{label}: expected API Gateway's own Not Found envelope, got {body[:300]!r}"
        )
        assert _routed(body) is None, f"{label}: the backend was reached: {body[:200]!r}"

    status, _, body = _http(ctx, "GET", control)
    assert status == 200 and _routed(body) == "GET /ip", (
        f"control must still serve after the negatives, got {status}: {body[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
