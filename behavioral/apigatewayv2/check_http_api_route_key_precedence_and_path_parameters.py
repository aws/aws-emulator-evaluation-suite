"""http-api-route-key-precedence-and-path-parameters."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-route-key-precedence-and-path-parameters"
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


_EVENT_ECHO_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(event),
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With overlapping route keys an HTTP API picks the most specific match (static, {id},
    {proxy+}, then $default) and extracts pathParameters; a second variable at a level is refused.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html
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
    target = f"integrations/{integ_id}"
    route_keys = ["GET /items/list", "GET /items/{id}", "GET /{proxy+}", "$default"]
    for rk in route_keys:
        agw.create_route(ApiId=api_id, RouteKey=rk, Target=target)
    listed = {r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items", [])}
    assert listed == set(route_keys), f"GetRoutes lost overlapping route keys: {sorted(listed)}"

    # One variable name per hierarchical level: a second one at /items/ is refused in either
    # creation order, greedy or not, so the greedy route is declared at the root instead.
    for conflicting in ("GET /items/{proxy+}", "GET /items/{name}"):
        try:
            agw.create_route(ApiId=api_id, RouteKey=conflicting, Target=target)
            raise AssertionError(
                f"route key {conflicting!r} must be refused: it introduces a second variable "
                "at the /items/ level, which already has the variable of 'GET /items/{id}'"
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            assert err.get("Code") == "ConflictException", (
                f"{conflicting}: expected ConflictException, got {err.get('Code')}: "
                f"{err.get('Message')}"
            )
            expected = (
                'The provided route key "%s" has a conflicting variable on the same '
                'hierarchical level as "GET /items/{id}"' % conflicting
            )
            assert err.get("Message") == expected, (
                f"the refusal must name both route keys and the reason; expected "
                f"{expected!r}, got {err.get('Message')!r}"
            )
    # Effect absent: neither refused route was created.
    still = {r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items", [])}
    assert still == set(route_keys), (
        f"a refused CreateRoute changed the route table: {sorted(still)}"
    )

    # ... and the rule is about a single hierarchical LEVEL, not about variables generally:
    # a variable under a different METHOD and a variable at a deeper level are both accepted.
    # The $default leg below therefore uses PUT, which none of these method-scoped keys claim.
    for allowed in ("POST /items/{id}", "GET /items/{id}/sub/{childId}"):
        agw.create_route(ApiId=api_id, RouteKey=allowed, Target=target)

    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    _allow_apigw_invoke(ctx, fn["name"], api_id)

    # First request also absorbs execute-api DNS + auto-deploy propagation.
    status, body = _poll_http(_invoke_url(ctx, api_endpoint, "/items/list", stage="$default"), 200)
    assert status == 200, f"expected 200 for GET /items/list, got {status}: {body}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "GET /items/list", (
        f"static route key must win over the path-variable routes, got {ev.get('routeKey')}"
    )

    status, body = _poll_http(_invoke_url(ctx, api_endpoint, "/items/42", stage="$default"), 200)
    assert status == 200, f"expected 200 for GET /items/42, got {status}: {body}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "GET /items/{id}", (
        f"single path variable must win over greedy, got {ev.get('routeKey')}"
    )
    assert ev.get("pathParameters") == {"id": "42"}, (
        f"pathParameters must extract id=42, got {ev.get('pathParameters')}"
    )

    status, body = _poll_http(_invoke_url(ctx, api_endpoint, "/items/a/b/c", stage="$default"), 200)
    assert status == 200, f"expected 200 for GET /items/a/b/c, got {status}: {body}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "GET /{proxy+}", (
        f"a multi-segment path cannot match the single-variable route and must fall to the "
        f"greedy route, got {ev.get('routeKey')}"
    )
    assert ev.get("pathParameters") == {"proxy": "items/a/b/c"}, (
        f"greedy pathParameters must capture every remaining segment "
        f"(proxy=items/a/b/c), got {ev.get('pathParameters')}"
    )

    status, body = _poll_http(
        _invoke_url(ctx, api_endpoint, "/items/list", stage="$default"),
        200,
        method="PUT",
        headers={"Content-Type": "application/json"},
        body=b'{"m":1}',
    )
    assert status == 200, f"expected 200 for PUT /items/list via $default, got {status}: {body}"
    ev = json.loads(body)
    assert ev.get("routeKey") == "$default", (
        f"PUT matches no method-scoped key so $default must win, got {ev.get('routeKey')}"
    )
    assert ev.get("rawPath") == "/items/list", (
        f"$default must still report the real rawPath, got {ev.get('rawPath')}"
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
