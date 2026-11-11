"""apigw-lambda-invoke-throttled-returns-default-integration-failure."""
from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-lambda-invoke-throttled-returns-default-integration-failure"
GROUP = "throttling"
SERVICES = ["apigateway", "lambda"]

_HANDLER = """
def lambda_handler(event, context):
    return {"statusCode": 200, "body": "served"}
"""


# ===== helpers (self-contained) =====
def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff: the
    apigateway control plane rate-limits mutating calls per account."""
    import random
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(10.0, 1.0 * (2 ** attempt)) + random.uniform(0, 0.3))


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root resource not found on {api_id!r}")


def _http(method, url, *, verify=True):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed https scheme
            req, timeout=20, context=_ssl_context(verify)
        ) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read().decode()
    except OSError as exc:
        return None, {}, repr(exc)


def _budget_s(ctx, want):
    """`want` seconds, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want if left is None else max(1.0, min(want, left - 10.0))


def _poll(ctx, fn, predicate, *, timeout_s=150.0, interval_s=3.0, description="result"):
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        result = fn()
        if predicate(*result):
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{description} not observed within {budget:.0f}s; last={result!r}")
        time.sleep(interval_s)


def _create_lambda(ctx, handler_code):
    """A Lambda whose execution role is scoped to log writes; waits for Active."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-apigw-intfail-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(lambda: _teardown(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ), "NoSuchEntity"))

    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-apigw-intfail-fn-")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.13", Role=role_arn,
                Handler="lambda_function.lambda_handler", Code={"ZipFile": buf.getvalue()},
                Timeout=10, MemorySize=128, Tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException", "AccessDeniedException",
            ):
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll(
        ctx, lambda: (_try_create(),), lambda c: c is not None,
        timeout_s=120.0, interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )[0]
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll(
        ctx, lambda: (lam.get_function_configuration(FunctionName=name),),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0, interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return name, created["FunctionArn"]


def _delete_role(iam, role_name):
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _teardown(undo, *not_found):
    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _reap_log_group(logs, name, *, reads=3, interval_s=5.0, budget_s=180.0):
    """Delete log group `name` until `reads` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes"
                )
            time.sleep(interval_s)
# ===== end helpers =====


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda proxy integration starved of concurrency fails the gateway's own Invoke
    call, answered with the exact default INTEGRATION_FAILURE envelope (500); restoring
    concurrency recovers the real response."""
    ag = ctx.client("apigateway")
    lam = ctx.client("lambda")
    account_id = ctx.account

    fn_name, fn_arn = _create_lambda(ctx, _HANDLER)

    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    lam.add_permission(
        FunctionName=fn_name, StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/GET/",
    )
    root_id = _root_id(ag, api_id)
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"))
    integration_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}/invocations"
    )
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="AWS_PROXY",
        integrationHttpMethod="POST", uri=integration_uri,
    ))

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    stage_name = "test"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage_name, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage_name)))

    url = f"{ctx.rest_api_url(api_id, stage_name)}/"

    # Positive control first: the integration genuinely works before concurrency is starved.
    status, _headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 200,
        description=f"GET {url} to be served before concurrency is starved",
    )
    assert text == "served", f"precondition: expected the handler's own body, got {text!r}"

    lam.put_function_concurrency(FunctionName=fn_name, ReservedConcurrentExecutions=0)
    ctx.on_cleanup(lambda: lam.delete_function_concurrency(FunctionName=fn_name))

    status, headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 500,
        description=f"GET {url} to answer 500 once concurrency is starved to 0",
    )
    assert status == 500, f"expected 500 once Invoke itself is throttled, got {status!r}: {text!r}"
    assert text == '{"message": "Internal server error"}', (
        f"expected the exact default INTEGRATION_FAILURE body, got {text!r}"
    )
    assert headers.get("x-amzn-errortype") == "InternalServerErrorException", (
        f"expected x-amzn-ErrorType: InternalServerErrorException, got "
        f"{headers.get('x-amzn-errortype')!r} (all headers {headers!r})"
    )

    # Control: restoring concurrency lets the real response through again.
    lam.delete_function_concurrency(FunctionName=fn_name)
    status, _headers, text = _poll(
        ctx, lambda: _http("GET", url, verify=ctx.http_verify), lambda s, h, t: s == 200,
        timeout_s=120.0,
        description=f"GET {url} to recover once concurrency is restored",
    )
    assert text == "served", f"expected recovery to the handler's own body, got {text!r}"


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
