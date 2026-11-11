"""http-api-lambda-proxy-function-error-returns-500-while-twin-route-serves."""
from __future__ import annotations

import io
import json
import random
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-lambda-proxy-function-error-returns-500-while-twin-route-serves"
GROUP = 'invoke'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# Data-plane failure marker: a detail containing it reads as a fidelity failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Bounded wait for execute-api propagation.
_CONVERGE_WAIT_S = 40

def _gone_tolerant(fn):
    """Teardown that tolerates NotFoundException: the check deletes the API itself on success."""
    def run_it():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    return run_it

def _not_found(fn, what, message):
    """fn() must raise NotFoundException with HTTP 404 and exactly ``message``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert got == ("NotFoundException", message), (
            f"{what}: expected ('NotFoundException', {message!r}), got {got!r}"
        )
        assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
        return
    raise AssertionError(f"{what}: expected NotFoundException, but the call SUCCEEDED: {result!r}")


def _ssl_context(verify):
    """The TLS trust ctx.http_verify names: False -> unverified, a path -> that CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method, url, body=None, headers=None):
    """HTTP request via urllib, trusting what ctx.http_verify names. Returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(_gone_tolerant(lambda: agw.delete_api(ApiId=api["ApiId"])))
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
        # The check deletes the role itself on success; only IAM's NoSuchEntity is tolerated.
        try:
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return arn, role_name


def _create_lambda(ctx, handler_code):
    """Create a python Lambda; return {name, arn}. Registers teardown."""
    role_arn, role_name = _create_lambda_role(ctx)
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
            ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name),
                                     "ResourceNotFoundException"))
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if arn is None:
        raise last_err or RuntimeError(f"failed to create lambda {name}")
    _deadline = time.monotonic() + 40
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= _deadline:
            raise AssertionError(f"lambda {name} not Active within 40s; last State {state!r}")
        time.sleep(2.0)
    return {"name": name, "arn": arn, "role_name": role_name}


def _allow_apigw_invoke(ctx, fn_name, api_id):
    lam = ctx.client("lambda")
    src = f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*"
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

def _invoke_url(ctx, api_id, path, stage=None):
    p = path.lstrip("/")
    stg = stage or "$default"
    return f"{ctx.api_url(api_id, stg)}/{p}"

def _tolerant(fn, code):
    """Teardown that tolerates exactly the service's own not-found code."""
    def run_it():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != code:
                raise
    return run_it


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


_HANDLER = """
import json
def lambda_handler(event, context):
    token = (event.get("queryStringParameters") or {}).get("token", "")
    if event.get("rawPath") == "/boom":
        raise RuntimeError("handler failure " + token)
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"ok": token, "routeKey": event.get("routeKey")})}
"""


def _poll_ok(ctx, url):
    """GET until the route answers 200 (execute-api and auto-deploy propagation)."""
    status, text = None, ""
    last_exc = None
    deadline = time.monotonic() + _CONVERGE_WAIT_S
    while time.monotonic() < deadline:
        try:
            status, _, text = _http(ctx, "GET", url)
        except Exception as exc:  # noqa: BLE001 — DNS/connect warm-up, retry within the budget
            last_exc = exc
            time.sleep(3)
            continue
        if status == 200:
            break
        time.sleep(3)
    assert status == 200, (
        f"{DATAPLANE_MARKER}: expected 200 from invoke URL {url}, got {status}: {text}"
        + (f" (last transport error: {type(last_exc).__name__}: {last_exc})" if last_exc else "")
    )
    return text


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """When the proxied Lambda raises, the HTTP API answers 500 with its fixed Internal Server Error
    body and leaks nothing of the exception, while a twin route on the same function and stage keeps
    answering the function's own 200 body before and after the failure."""
    rng = random.SystemRandom()
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _HANDLER)
    api_id = _create_http_api(ctx)
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=fn["arn"],
        IntegrationMethod="POST", PayloadFormatVersion="2.0",
    )
    for key in ("GET /ok", "GET /boom"):
        agw.create_route(ApiId=api_id, RouteKey=key, Target=f"integrations/{integ['IntegrationId']}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(_gone_tolerant(lambda: agw.delete_stage(ApiId=api_id, StageName="$default")))
    _allow_apigw_invoke(ctx, fn["name"], api_id)

    token = f"t{rng.randrange(10**9):09d}"
    ok_url = _invoke_url(ctx, api_id, "/ok") + f"?token={token}"
    boom_url = _invoke_url(ctx, api_id, "/boom") + f"?token={token}"
    expected_ok = {"ok": token, "routeKey": "GET /ok"}
    text = _poll_ok(ctx, ok_url)
    assert json.loads(text) == expected_ok, f"GET /ok before the failure: expected {expected_ok!r}, got {text!r}"

    status, _, text = _http(ctx, "GET", boom_url)
    assert status == 500, f"GET /boom with a raising function: expected 500, got {status}: {text}"
    assert json.loads(text) == {"message": "Internal Server Error"}, (
        f"GET /boom: expected the fixed body {{'message': 'Internal Server Error'}}, got {text!r}"
    )

    # Twin control: the same function behind the sibling route still serves.
    status, _, text = _http(ctx, "GET", ok_url)
    assert (status, json.loads(text)) == (200, expected_ok), (
        f"GET /ok after the failure: expected (200, {expected_ok!r}), got ({status}, {text!r})"
    )

    agw.delete_api(ApiId=api_id)
    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _not_found(lambda: agw.get_api(ApiId=api_id), "GetApi on the deleted API", api_gone)
    _not_found(lambda: agw.get_routes(ApiId=api_id), "GetRoutes on the deleted API", api_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
