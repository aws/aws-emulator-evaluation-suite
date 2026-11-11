"""lambda-authorizer-simple-response-explicit-deny-forbidden."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-authorizer-simple-response-explicit-deny-forbidden"
GROUP = 'authorizers'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


def _http(method, url, body=None, headers=None):
    """HTTP request via urllib; returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _poll_http(url, headers, want, timeout_s=120):
    """Poll the invoke URL until status == want (tolerating settling noise)."""
    status, body = None, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url, headers=headers or {})
        except Exception:
            time.sleep(3)
            continue
        if status == want:
            return status, body
        time.sleep(3)
    return status, body


def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"], api["ApiEndpoint"]


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
    """Create a python Lambda; return {name, arn}. Registers teardown.

    CreateFunction is retried on "cannot be assumed" because IAM role propagation is asynchronous.
    """
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
    deadline = time.monotonic() + 60
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


# A simple-response (format 2.0) REQUEST authorizer that EXPLICITLY denies a
# recognized "deny me" token, rather than merely failing to recognize an unknown one.
_EXPLICIT_DECISION_AUTHORIZER_CODE = """
def lambda_handler(event, context):
    headers = event.get("headers") or {}
    token = headers.get("authorization", "")
    return {"isAuthorized": token == "sim2real-let-me-in"}
"""

_BACKEND_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": "v2-deny-check-backend-ok"}),
    }
"""

_VALID_TOKEN = "sim2real-let-me-in"
_DENY_TOKEN = "sim2real-deny-me"


def _deploy_authorized_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    authz_fn = _create_lambda(ctx, _EXPLICIT_DECISION_AUTHORIZER_CODE)
    backend_fn = _create_lambda(ctx, _BACKEND_CODE)
    api_id, api_endpoint = _create_http_api(ctx)
    integ = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=backend_fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{authz_fn['arn']}/invocations"
    )
    authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-deny-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        AuthorizerResultTtlInSeconds=0,  # no caching -> authorizer runs every request
    )["AuthorizerId"]
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /secure",
        Target=f"integrations/{integ['IntegrationId']}",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    _allow_apigw_invoke(ctx, backend_fn["name"], api_id)
    lam = ctx.client("lambda")
    authz_src = (
        f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:"
        f"{api_id}/authorizers/{authorizer_id}"
    )
    try:
        lam.add_permission(
            FunctionName=authz_fn["name"],
            StatementId="apigw-authorizer-invoke",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=authz_src,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e) and "already exists" not in str(e).lower():
            raise
    return {"url": _invoke_url(ctx, api_endpoint, "/secure", stage="$default")}


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A simple-response (format 2.0) REQUEST authorizer is enforced: an allowed token reaches the
    backend, and an explicit isAuthorized=false for a recognized token returns 403 Forbidden.
    """
    api = _deploy_authorized_http_api(ctx)

    allow_status, allow_body = _poll_http(
        api["url"], {"Authorization": _VALID_TOKEN}, want=200
    )
    assert allow_status == 200, (
        f"precondition: the valid-token call should be 200, got {allow_status}: {allow_body}"
    )
    data = json.loads(allow_body)
    assert data.get("marker") == "v2-deny-check-backend-ok", f"unexpected backend body: {data}"

    deny_status, _, deny_body = _http(
        "GET", api["url"], headers={"Authorization": _DENY_TOKEN}
    )
    assert deny_status == 403, (
        f"expected 403 Forbidden for an explicit isAuthorized=false decision, "
        f"got {deny_status}: {deny_body}"
    )
    deny_payload = json.loads(deny_body)
    assert deny_payload == {"message": "Forbidden"}, (
        f"expected the exact default-gateway-response body {{'message': 'Forbidden'}}, "
        f"got {deny_payload!r}"
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
