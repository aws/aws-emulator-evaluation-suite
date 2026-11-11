"""apigw-http-api-lambda-integration-positive."""
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

CHECK = "apigw-http-api-lambda-integration-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_LAMBDA_CODE = """
import json

def handler(event, context):
    qs = event.get("queryStringParameters") or {}
    msg = qs.get("msg", "")
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"echoed": msg, "routeKey": event.get("routeKey", "")}),
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP API (v2) Lambda proxy integration invokes the target function and returns its response through the endpoint."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    apigw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-httpapi-")
    api = apigw.create_api(
        Name=name, ProtocolType="HTTP", Tags={"sim2real:managed": "true"}
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(_tolerant(lambda: apigw.delete_api(ApiId=api_id), "NotFoundException"))

    integration = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        PayloadFormatVersion="2.0",
        IntegrationMethod="POST",
    )
    apigw.create_route(
        ApiId=api_id, RouteKey="GET /echo", Target=f"integrations/{integration['IntegrationId']}"
    )
    apigw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )

    # The published host is reached only through the target's own stage URL.
    url = f"{ctx.stage_url(api['ApiEndpoint'], '$default')}/echo?msg=hello123"
    body = _poll_http_get(url, timeout_s=90, verify=ctx.http_verify)
    payload = json.loads(body)
    assert payload["echoed"] == "hello123", f"expected echoed='hello123', got {payload!r}"
    assert payload["routeKey"] == "GET /echo", f"expected routeKey='GET /echo', got {payload!r}"

    # Tear down in reverse dependency order and prove each resource gone.
    _gone_http_api(ctx, api_id)
    _gone_lambda(ctx, fn["name"])
    _gone_role(ctx, role_arn.rsplit("/", 1)[-1])


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lamrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_tolerant(_cleanup, "NoSuchEntity"))
    return role_arn


def _create_lambda_function(ctx, role_arn, code, handler="index.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    last_err = None
    resp = None
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(_tolerant(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))

    deadline = time.monotonic() + 60
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            break
        time.sleep(2)
    if state != "Active":
        raise AssertionError(f"lambda function {name} never became Active (last state={state})")

    return {"name": name, "arn": resp["FunctionArn"]}


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _poll_http_get(url, timeout_s=90.0, interval_s=3.0, verify=True) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10, context=_ssl_context(verify)) as resp:
                if resp.status == 200:
                    return resp.read().decode()
                last_exc = AssertionError(f"unexpected status {resp.status}")
        except urllib.error.HTTPError as e:
            last_exc = e
        except urllib.error.URLError as e:
            last_exc = e
        time.sleep(interval_s)
    if isinstance(last_exc, urllib.error.URLError) and not isinstance(last_exc, urllib.error.HTTPError):
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: nothing answered at the HTTP API stage URL {url} within "
            f"{timeout_s}s, so the Lambda integration could not be invoked: {last_exc}"
        ) from last_exc
    raise AssertionError(f"endpoint never returned 200 within {timeout_s}s: {last_exc}")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


# ===== teardown proofs (GONE: three beats per family) =====
#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message {msg[:200]!r}, expected {message!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    lam.delete_function(FunctionName=name)
    nf = ("ResourceNotFoundException",)
    gone = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}", gone)
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    _poll_refused(
        lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}", f"{gone}:$LATEST"
    )


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    gone = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", gone)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", gone,
    )


def _gone_http_api(ctx, api_id: str) -> None:
    v2 = ctx.client("apigatewayv2")
    v2.delete_api(ApiId=api_id)
    nf = ("NotFoundException",)
    gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _poll_refused(lambda: v2.get_api(ApiId=api_id), nf, 404, f"GetApi {api_id}", gone)
    listed = {a["ApiId"] for a in _paged(v2, "get_apis", "Items")}
    assert api_id not in listed, f"GetApis still lists deleted API {api_id}"
    _refused(lambda: v2.create_route(ApiId=api_id, RouteKey="GET /gone"), nf, 404, f"CreateRoute {api_id}", gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
