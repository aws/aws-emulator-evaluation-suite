"""delete-stage-stops-serving-requests."""
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

CHECK = "delete-stage-stops-serving-requests"
GROUP = "invoke"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# Marks a missing data-plane answer as a fidelity failure rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Bound on waiting for execute-api propagation after a stage is created or deleted.
_CONVERGE_WAIT_S = 200

def _gone_tolerant(fn):
    """Teardown that tolerates NotFoundException: the check deletes the API itself on success."""
    def run_it():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    return run_it

def _not_found(fn, what, expected):
    """fn() must raise NotFoundException with HTTP 404 and exactly the expected message."""
    try:
        result = fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message") or ""
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert code == "NotFoundException", f"{what}: expected NotFoundException, got {code!r}"
        assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
        assert message == expected, f"{what}: expected message {expected!r}, got {message!r}"
        return
    raise AssertionError(f"{what}: expected NotFoundException, but the call SUCCEEDED: {result!r}")

def _ssl_context(verify):
    """The TLS trust ctx.http_verify names: False -> unverified, a path -> that CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method, url, body=None, headers=None):
    """Send one HTTP request trusting what ctx.http_verify names; return (status, headers, body)."""
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
    _deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= _deadline:
            raise AssertionError(f"lambda {name} active not met within 60s")
        time.sleep(2.0)
    return {"name": name, "arn": arn, "role_name": role_name}

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

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two auto-deployed stages of one HTTP API serve the same Lambda route; DeleteStage on one
    stops its invoke URL answering (404) while the twin stage keeps serving the same route.
    """
    agw = ctx.client("apigatewayv2")
    handler_code = """
import json
def lambda_handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"stage": (event.get("requestContext") or {}).get("stage")})}
"""
    fn = _create_lambda(ctx, handler_code)
    api_id, api_endpoint = _create_http_api(ctx)
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=fn["arn"],
        IntegrationMethod="POST", PayloadFormatVersion="2.0",
    )
    agw.create_route(
        ApiId=api_id, RouteKey="GET /hello", Target=f"integrations/{integ['IntegrationId']}"
    )
    for stage in ("live", "twin"):
        agw.create_stage(ApiId=api_id, StageName=stage, AutoDeploy=True)
        ctx.on_cleanup(_gone_tolerant(lambda s=stage: agw.delete_stage(ApiId=api_id, StageName=s)))
    _allow_apigw_invoke(ctx, fn["name"], api_id)
    live_url = _invoke_url(ctx, api_endpoint, "/hello", stage="live")
    twin_url = _invoke_url(ctx, api_endpoint, "/hello", stage="twin")

    for stage, url in (("live", live_url), ("twin", twin_url)):
        status, body = _await(ctx, url, lambda s: s == 200)
        assert status == 200, (
            f"{DATAPLANE_MARKER}: expected 200 from stage {stage!r} at {url}, got {status}: {body}"
        )
        assert json.loads(body).get("stage") == stage, f"stage {stage!r} answered {body!r}"

    agw.delete_stage(ApiId=api_id, StageName="live")
    status, body = _await(ctx, live_url, lambda s: s == 404)
    assert status == 404, f"the deleted stage's URL still answers {status}: {body!r}"
    assert json.loads(body) == {"message": "Not Found"}, f"deleted stage body: {body!r}"
    _not_found(
        lambda: agw.get_stage(ApiId=api_id, StageName="live"),
        "GetStage on the deleted stage",
        "Invalid stage identifier specified",
    )

    status, body = _http(ctx, "GET", twin_url)[0::2]
    assert status == 200 and json.loads(body).get("stage") == "twin", (
        f"the twin stage stopped serving after the other stage was deleted: {status} {body!r}"
    )


def _await(ctx, url, done):
    """GET url until done(status) or the budget ends; returns the last (status, body)."""
    status, body, last_exc = None, "", None
    deadline = time.monotonic() + _CONVERGE_WAIT_S
    while time.monotonic() < deadline:
        try:
            status, _, body = _http(ctx, "GET", url)
        except Exception as exc:  # noqa: BLE001 - DNS/connect warm-up, retried within the budget
            last_exc = exc
            time.sleep(3)
            continue
        if done(status):
            return status, body
        time.sleep(3)
    if status is None and last_exc is not None:
        return None, f"last transport error: {type(last_exc).__name__}: {last_exc}"
    return status, body


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
    """Delete the log group Lambda creates on a function's first log line, if it exists."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
