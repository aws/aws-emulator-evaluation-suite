"""http-api-lambda-proxy-post-path-parameter-returns-the-functions-status-headers-and-body."""
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

CHECK = "http-api-lambda-proxy-post-path-parameter-returns-the-functions-status-headers-and-body"
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
import base64, json
def lambda_handler(event, context):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    body = json.loads(raw)
    order = event["pathParameters"]["orderId"]
    return {
        "statusCode": int(body["status"]),
        "headers": {"Content-Type": "application/json", "x-order-id": order},
        "body": json.dumps({
            "orderId": order,
            "total": sum(body["nums"]),
            "routeKey": event.get("routeKey"),
            "method": event["requestContext"]["http"]["method"],
            "rawQueryString": event.get("rawQueryString"),
        }),
    }
"""


def _poll_status(ctx, url, body, want_status):
    """POST until the route answers ``want_status`` (execute-api and auto-deploy propagation)."""
    status, headers, text = None, {}, ""
    last_exc = None
    deadline = time.monotonic() + _CONVERGE_WAIT_S
    while time.monotonic() < deadline:
        try:
            status, headers, text = _http(ctx, "POST", url, body=body,
                                          headers={"Content-Type": "application/json"})
        except Exception as exc:  # noqa: BLE001 — DNS/connect warm-up, retry within the budget
            last_exc = exc
            time.sleep(3)
            continue
        if status == want_status:
            break
        time.sleep(3)
    assert status == want_status, (
        f"{DATAPLANE_MARKER}: expected {want_status} from invoke URL {url}, got {status}: {text}"
        + (f" (last transport error: {type(last_exc).__name__}: {last_exc})" if last_exc else "")
    )
    return {k.lower(): v for k, v in headers.items()}, text


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A POST to an HTTP API {orderId} route with a Lambda proxy integration answers with the
    status code, headers and body the function computed from that request's path parameter,
    query string and JSON body; the deleted API is then unreadable and refuses new routes."""
    rng = random.SystemRandom()
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _HANDLER)
    api_id = _create_http_api(ctx)
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=fn["arn"],
        IntegrationMethod="POST", PayloadFormatVersion="2.0",
    )
    agw.create_route(ApiId=api_id, RouteKey="POST /orders/{orderId}",
                     Target=f"integrations/{integ['IntegrationId']}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(_gone_tolerant(lambda: agw.delete_stage(ApiId=api_id, StageName="$default")))
    _allow_apigw_invoke(ctx, fn["name"], api_id)

    for want_status in rng.sample([201, 202, 409, 422], 2):
        order = f"o{rng.randrange(10**9):09d}"
        nums = [rng.randint(1, 1000) for _ in range(rng.randint(2, 6))]
        query = f"tag={rng.randrange(10**6)}"
        url = _invoke_url(ctx, api_id, f"/orders/{order}") + f"?{query}"
        headers, text = _poll_status(
            ctx, url, json.dumps({"status": want_status, "nums": nums}).encode(), want_status)
        assert headers.get("x-order-id") == order, (
            f"expected the function's x-order-id header {order!r}, got {headers.get('x-order-id')!r}"
        )
        assert headers.get("content-type", "").startswith("application/json"), (
            f"expected the function's application/json content-type, got {headers.get('content-type')!r}"
        )
        expected = {"orderId": order, "total": sum(nums), "routeKey": "POST /orders/{orderId}",
                    "method": "POST", "rawQueryString": query}
        assert json.loads(text) == expected, f"POST {url}: expected body {expected!r}, got {text!r}"

    agw.delete_api(ApiId=api_id)
    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _not_found(lambda: agw.get_api(ApiId=api_id), "GetApi on the deleted API", api_gone)
    survivors = [a.get("ApiId") for a in _all_apis(agw) if a.get("ApiId") == api_id]
    assert survivors == [], f"deleted API still listed by GetApis: {survivors!r}"
    _not_found(lambda: agw.create_route(ApiId=api_id, RouteKey="GET /dead"),
               "CreateRoute on the deleted API", api_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
