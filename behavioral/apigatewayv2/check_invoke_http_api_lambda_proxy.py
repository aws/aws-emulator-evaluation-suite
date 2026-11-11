"""invoke-http-api-lambda-proxy."""
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

CHECK = "invoke-http-api-lambda-proxy"
GROUP = 'invoke'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

# Data-plane failure marker: a detail containing it reads as a fidelity failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Bounded wait for execute-api propagation.
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

def _all_apis(agw):
    """Every API GetApis returns, following NextToken."""
    items, token = [], None
    while True:
        page = agw.get_apis(**({"NextToken": token} if token else {}))
        items += page.get("Items", [])
        token = page.get("NextToken")
        if not token:
            return items

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
    """A real GET to the HTTP API's AWS_PROXY invoke URL returns the Lambda's payload 2.0 response
    built from the request; the deleted API, its Lambda and its role are then unreadable,
    unlisted and refuse further calls."""
    agw = ctx.client("apigatewayv2")
    handler_code = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "marker": "v2-lambda-proxy-ok",
            "rawPath": event.get("rawPath"),
            "method": (event.get("requestContext") or {}).get("http", {}).get("method"),
        }),
    }
"""
    # A Lambda creation failure is a prerequisite failure, not an API Gateway one.
    fn = _create_lambda(ctx, handler_code)

    api_id, api_endpoint = _create_http_api(ctx)
    integ = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )
    agw.create_route(
        ApiId=api_id, RouteKey="GET /hello", Target=f"integrations/{integ['IntegrationId']}"
    )
    # $default AutoDeploy stage -> the route is served without an explicit deploy.
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(_gone_tolerant(lambda: agw.delete_stage(ApiId=api_id, StageName="$default")))

    _allow_apigw_invoke(ctx, fn["name"], api_id)

    url = _invoke_url(ctx, api_endpoint, "/hello", stage="$default")

    # execute-api DNS + auto-deploy propagation is a few seconds; poll and
    # tolerate transient 403/404/429/5xx while it settles.
    status, body = None, ""
    last_exc: Exception | None = None
    deadline = time.monotonic() + _CONVERGE_WAIT_S
    while time.monotonic() < deadline:
        try:
            status, _, body = _http(ctx, "GET", url)
        except Exception as exc:  # noqa: BLE001 — DNS/connect warm-up, retry within the budget
            # Kept: if the budget expires this is the only evidence of why.
            last_exc = exc
            time.sleep(3)
            continue
        if status == 200:
            break
        time.sleep(3)

    # Marked: the target built this invoke URL itself, so not serving it is a data-plane fidelity
    # failure even when the transport error looks like an environment problem.
    assert status == 200, (
        f"{DATAPLANE_MARKER}: expected 200 from invoke URL {url}, got {status}: {body}"
        + (f" (last transport error: {type(last_exc).__name__}: {last_exc})" if last_exc else "")
    )
    data = json.loads(body)
    assert data.get("marker") == "v2-lambda-proxy-ok", f"unexpected proxy body: {data}"
    assert data.get("rawPath") == "/hello", (
        f"expected the proxy event's rawPath to be the requested '/hello', got {data.get('rawPath')!r}"
    )
    assert data.get("method") == "GET", (
        f"expected the proxy event's requestContext.http.method to be 'GET', got {data.get('method')!r}"
    )


    agw.delete_api(ApiId=api_id)
    # Beat 1: the by-id read is NotFoundException 404.
    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _not_found(lambda: agw.get_api(ApiId=api_id), "GetApi on the deleted API", api_gone)
    # Beat 2: the deleted API is absent from GetApis.
    survivors = [a.get("ApiId") for a in _all_apis(agw) if a.get("ApiId") == api_id]
    assert survivors == [], f"deleted API still listed by GetApis: {survivors!r}"
    # Beat 3: a mutation on the dead id is refused.
    _not_found(
        lambda: agw.create_route(ApiId=api_id, RouteKey="GET /dead"),
        "CreateRoute on the deleted API", api_gone,
    )

    # The Lambda function this integration invoked: deleted, then unreadable, unlisted, uninvocable.
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=fn["name"])
    fn_gone = ("ResourceNotFoundException", f"Function not found: {fn['arn']}")
    _poll_refused(lambda: lam.get_function(FunctionName=fn["name"]), fn_gone, 404,
                  "GetFunction on the deleted function")
    listed_fns = [f["FunctionName"] for page in lam.get_paginator("list_functions").paginate()
                  for f in page["Functions"]]
    assert fn["name"] not in listed_fns, f"deleted function {fn['name']!r} is still listed by ListFunctions"
    # Invoke defaults to the $LATEST qualifier, which Lambda's not-found message names explicitly;
    # it keeps reaching a just-deleted function for a while on AWS, so it converges like GetFunction.
    invoke_fn_gone = ("ResourceNotFoundException", f"Function not found: {fn['arn']}:$LATEST")
    _poll_refused(lambda: lam.invoke(FunctionName=fn["name"], Payload=b"{}"), invoke_fn_gone, 404,
                  "Invoke on the deleted function")

    # Its execution role: deleted, then unreadable, unlisted, and refuses a policy put.
    iam = ctx.client("iam")
    role_name = fn["role_name"]
    iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
    iam.delete_role(RoleName=role_name)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    _poll_refused(lambda: iam.get_role(RoleName=role_name), role_gone, 404, "GetRole on the deleted role")
    listed_roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate(PathPrefix="/sim2real/")
                    for r in page["Roles"]]
    assert role_name not in listed_roles, f"deleted role {role_name!r} is still listed by ListRoles"
    _refused(lambda: iam.put_role_policy(RoleName=role_name, PolicyName="dead",
                                         PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                                             {"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "*"}]})),
             role_gone, 404, "PutRolePolicy on the deleted role")


def _tolerant(fn, code):
    """Teardown that tolerates exactly the service's own not-found code."""
    def run_it():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != code:
                raise
    return run_it


def _refused(fn, expected, status, what):
    """fn() must raise the ``expected`` (code, message) with HTTP `status`."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        got_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert got == expected, f"{what}: expected {expected}, got {got!r}"
        assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
        return
    raise AssertionError(f"{what}: expected {expected}, but the call SUCCEEDED: {result!r}")


def _poll_refused(fn, expected, status, what, timeout_s=_CONVERGE_WAIT_S):
    """Poll fn() until it raises (deletes converge asynchronously), then grade the refusal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s}s after the delete")
        time.sleep(2.0)
    _refused(fn, expected, status, what)


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
