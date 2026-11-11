"""import-api-payload-format-version-extension-honored."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-api-payload-format-version-extension-honored"
GROUP = 'import-export'
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


def _poll_http(url, want_status, timeout_s=120):
    """Poll GET url until status == want_status (tolerating settling noise)."""
    status, body = None, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url)
        except Exception:
            time.sleep(3)
            continue
        if status == want_status:
            return status, body
        time.sleep(3)
    return status, body


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


_ECHO_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(event),
    }
"""


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


def _spec(ctx, fn_arn):
    invocation_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    )

    def _integration(payload_format_version):
        return {
            "type": "AWS_PROXY",
            "httpMethod": "POST",
            "uri": invocation_uri,
            "payloadFormatVersion": payload_format_version,
        }

    return {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-behav-payload-format-version", "version": "1.0"},
        "paths": {
            "/echo-v1": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": _integration("1.0"),
                }
            },
            "/echo-v2": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": _integration("2.0"),
                }
            },
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ImportApi honors each route's payloadFormatVersion from its integration extension: two routes
    from one document, at 1.0 and 2.0, deliver the matching distinct event shapes to one Lambda.
    """
    fn = _create_lambda(ctx, _ECHO_CODE)

    agw = ctx.client("apigatewayv2")
    spec = _spec(ctx, fn["arn"])
    imported = agw.import_api(Body=json.dumps(spec))
    api_id = imported["ApiId"]

    def _cleanup_api():
        try:
            agw.delete_api(ApiId=api_id)
        except agw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup_api)

    routes = {r["RouteKey"]: r for r in agw.get_routes(ApiId=api_id)["Items"]}
    assert set(routes) == {"GET /echo-v1", "GET /echo-v2"}, (
        f"expected both imported routes, got {sorted(routes)}"
    )
    for route_key, want_version in (("GET /echo-v1", "1.0"), ("GET /echo-v2", "2.0")):
        integration_id = routes[route_key]["Target"].split("/")[-1]
        integ = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
        assert integ.get("PayloadFormatVersion") == want_version, (
            f"{route_key}: expected PayloadFormatVersion {want_version!r}, "
            f"got {integ.get('PayloadFormatVersion')!r}"
        )

    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    _allow_apigw_invoke(ctx, fn["name"], api_id)

    status, body = _poll_http(f"{ctx.stage_url(imported['ApiEndpoint'], '$default')}/echo-v1", 200)
    assert status == 200, f"GET /echo-v1: expected 200, got {status}: {body}"
    event_v1 = json.loads(body)
    assert event_v1.get("version") == "1.0", (
        f"a payloadFormatVersion=1.0 integration must deliver the 1.0 proxy event shape "
        f"(top-level version='1.0'), got {event_v1.get('version')!r}"
    )
    assert event_v1.get("httpMethod") == "GET", (
        f"a 1.0-format event must carry a top-level 'httpMethod', got {event_v1.get('httpMethod')!r}"
    )
    assert "rawPath" not in event_v1, (
        f"a 1.0-format event must not carry 'rawPath' (that is a 2.0-only field), "
        f"got rawPath={event_v1.get('rawPath')!r}"
    )

    status, body = _poll_http(f"{ctx.stage_url(imported['ApiEndpoint'], '$default')}/echo-v2", 200)
    assert status == 200, f"GET /echo-v2: expected 200, got {status}: {body}"
    event_v2 = json.loads(body)
    assert event_v2.get("version") == "2.0", (
        f"a payloadFormatVersion=2.0 integration must deliver the 2.0 proxy event shape "
        f"(top-level version='2.0'), got {event_v2.get('version')!r}"
    )
    assert event_v2.get("rawPath") == "/echo-v2", (
        f"a 2.0-format event must carry 'rawPath', got {event_v2.get('rawPath')!r}"
    )
    assert "httpMethod" not in event_v2, (
        f"a 2.0-format event must not carry the 1.0-only top-level 'httpMethod', "
        f"got httpMethod={event_v2.get('httpMethod')!r}"
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
