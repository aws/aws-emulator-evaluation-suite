"""import-api-then-reimport-changes-routing."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-api-then-reimport-changes-routing"
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


def _poll_http(url, want_marker, timeout_s=120):
    """Poll GET url until it serves a 200 whose JSON "marker" == want_marker.

    Right after ReimportApi the stage can briefly serve the previous backend; it converges.
    """
    status, body = None, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url)
        except Exception:
            time.sleep(3)
            continue
        if status == 200:
            try:
                if json.loads(body).get("marker") == want_marker:
                    return status, body
            except json.JSONDecodeError:
                pass
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


def _allow_apigw_invoke(ctx, fn_name, api_id, statement_id):
    lam = ctx.client("lambda")
    src = f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    try:
        lam.add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=src,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e) and "already exists" not in str(e).lower():
            raise


def _backend_code(marker):
    return (
        "import json\n"
        "def lambda_handler(event, context):\n"
        "    return {\n"
        "        'statusCode': 200,\n"
        "        'headers': {'Content-Type': 'application/json'},\n"
        f"        'body': json.dumps({{'marker': {marker!r}}}),\n"
        "    }\n"
    )


def _spec(ctx, route_path, fn_arn):
    invocation_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    )
    return {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-behav-import-reimport", "version": "1.0"},
        "paths": {
            route_path: {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "AWS_PROXY",
                        "httpMethod": "POST",
                        "uri": invocation_uri,
                        "payloadFormatVersion": "2.0",
                    },
                }
            }
        },
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An API imported with an AWS_PROXY integration serves live traffic to that backend, and
    ReimportApi pointing the same route at a different Lambda switches the backend on the same URL.
    """
    marker_a = ctx.unique_name("sim2real-behav-import-a-")
    marker_b = ctx.unique_name("sim2real-behav-import-b-")
    fn_a = _create_lambda(ctx, _backend_code(marker_a))
    fn_b = _create_lambda(ctx, _backend_code(marker_b))

    agw = ctx.client("apigatewayv2")
    spec_a = _spec(ctx, "/widgets", fn_a["arn"])

    imported = agw.import_api(Body=json.dumps(spec_a))
    api_id = imported["ApiId"]

    def _cleanup_api():
        try:
            agw.delete_api(ApiId=api_id)
        except agw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup_api)

    routes = agw.get_routes(ApiId=api_id)["Items"]
    assert len(routes) == 1, f"expected 1 route after import, got {routes!r}"
    assert routes[0]["RouteKey"] == "GET /widgets", (
        f"expected route key 'GET /widgets', got {routes[0]['RouteKey']!r}"
    )

    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    _allow_apigw_invoke(ctx, fn_a["name"], api_id, "apigw-invoke-a")
    _allow_apigw_invoke(ctx, fn_b["name"], api_id, "apigw-invoke-b")

    url = f"{ctx.stage_url(imported['ApiEndpoint'], '$default')}/widgets"

    status, body = _poll_http(url, marker_a)
    assert status == 200, f"expected 200 from the imported AWS_PROXY route, got {status}: {body}"
    assert json.loads(body).get("marker") == marker_a, (
        f"the imported route should serve Lambda A's marker {marker_a!r}, got body {body!r}"
    )

    spec_b = _spec(ctx, "/widgets", fn_b["arn"])
    agw.reimport_api(ApiId=api_id, Body=json.dumps(spec_b))

    routes_after = agw.get_routes(ApiId=api_id)["Items"]
    assert len(routes_after) == 1, f"expected 1 route after reimport, got {routes_after!r}"
    assert routes_after[0]["RouteKey"] == "GET /widgets", (
        f"expected route key 'GET /widgets' to survive reimport, got {routes_after[0]['RouteKey']!r}"
    )

    status, body = _poll_http(url, marker_b)
    assert status == 200, (
        f"expected 200 from the SAME route+stage after reimport, got {status}: {body}"
    )
    assert json.loads(body).get("marker") == marker_b, (
        f"after ReimportApi pointed 'GET /widgets' at Lambda B, the SAME invoke URL "
        f"should serve Lambda B's marker {marker_b!r}, got body {body!r} -- the gateway "
        f"never picked up the rewired backend"
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
