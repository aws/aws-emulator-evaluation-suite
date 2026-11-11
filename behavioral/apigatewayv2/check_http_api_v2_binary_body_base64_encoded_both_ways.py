"""http-api-v2-binary-body-base64-encoded-both-ways."""
from __future__ import annotations

import base64
import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-v2-binary-body-base64-encoded-both-ways"
GROUP = 'invoke'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


def _http(method, url, body=None, headers=None):
    """HTTP request via urllib; returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _poll_http(url, want, method="GET", headers=None, body=None, timeout_s=120):
    """Poll a URL until status == want (absorbing DNS/auto-deploy settling)."""
    status, resp_headers, resp_body = None, {}, b""
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


# Echoes what it received; on POST /bin it answers with fixed binary bytes, base64-encoded.
_BACKEND_CODE = """
import base64, json
def lambda_handler(event, context):
    if event.get("rawPath") == "/bin":
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/octet-stream"},
            "isBase64Encoded": True,
            "body": base64.b64encode(bytes(range(256))).decode(),
        }
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"isBase64Encoded": event.get("isBase64Encoded"), "body": event.get("body")}),
    }
"""

_PAYLOAD = bytes([0x00, 0xFF, 0x10, 0x80, 0x7F]) * 40


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Payload format 2.0 base64-encodes a binary request body for the Lambda (isBase64Encoded
    true), passes JSON verbatim (false), and decodes an isBase64Encoded response to raw bytes.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _BACKEND_CODE)
    api_id, api_endpoint = _create_http_api(ctx)
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for rk in ("POST /echo", "POST /bin"):
        agw.create_route(ApiId=api_id, RouteKey=rk, Target=f"integrations/{integ_id}")
    _allow_apigw_invoke(ctx, fn["name"], api_id)
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))

    status, _, body = _poll_http(
        _url(ctx, api_endpoint, "$default", "/echo"), 200, method="POST",
        headers={"Content-Type": "application/octet-stream"}, body=_PAYLOAD,
    )
    assert status == 200, f"binary POST /echo expected 200, got {status}: {body[:200]!r}"
    got = json.loads(body)
    assert got.get("isBase64Encoded") is True, (
        f"a binary request body must arrive with isBase64Encoded true, got {got.get('isBase64Encoded')!r}"
    )
    decoded = base64.b64decode(got.get("body") or "")
    assert decoded == _PAYLOAD, (
        f"the base64 body must decode to the {len(_PAYLOAD)} bytes sent, decoded {len(decoded)} "
        f"bytes (equal={decoded == _PAYLOAD})"
    )

    doc = {"order": 7, "note": "plain text"}
    status, _, body = _http(
        "POST", _url(ctx, api_endpoint, "$default", "/echo"),
        body=json.dumps(doc).encode(), headers={"Content-Type": "application/json"},
    )
    assert status == 200, f"JSON POST /echo expected 200, got {status}: {body[:200]!r}"
    got = json.loads(body)
    assert got.get("isBase64Encoded") is False, (
        f"a JSON request body must arrive with isBase64Encoded false, got {got.get('isBase64Encoded')!r}"
    )
    assert json.loads(got.get("body") or "null") == doc, f"the JSON body arrived as {got.get('body')!r}"

    status, hdrs, body = _http("POST", _url(ctx, api_endpoint, "$default", "/bin"), body=b"")
    assert status == 200, f"POST /bin expected 200, got {status}: {body[:200]!r}"
    assert body == bytes(range(256)), (
        f"a base64 response must reach the client decoded: expected the 256 raw bytes 0..255, got "
        f"{len(body)} bytes starting {body[:24]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
