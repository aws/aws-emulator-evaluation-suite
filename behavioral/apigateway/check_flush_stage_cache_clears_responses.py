"""flush-stage-cache-clears-responses."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "flush-stage-cache-clears-responses"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]

_BACKEND_CODE = """
import json
import uuid

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"requestId": str(uuid.uuid4())})}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FlushStageCache invalidates a stage's cached responses: with a Lambda integration that
    returns a fresh UUID per invocation, two rapid calls within the TTL return the same UUID
    (cache hit) and the first call after the flush returns a different one."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]

    start_time = time.monotonic()

    lambda_arn = _create_backend_lambda(ctx)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cache-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="cache")["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
    )

    source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/GET/cache"
    _allow_apigateway_invoke(ctx, lambda_arn, source_arn)

    stage_name = "sim"
    apigw.create_deployment(
        restApiId=api_id,
        stageName=stage_name,
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
    )

    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/*/*/caching/enabled", "value": "true"}],
    )

    url = f"{ctx.rest_api_url(api_id, stage_name)}/cache"

    # A new cache cluster can take over a minute to serve cached responses after it reports
    # AVAILABLE, so the cache-hit poll gets most of the run budget and the flush step a small slice.
    hit_timeout_s = max(30.0, 300.0 - (time.monotonic() - start_time) - 15.0)
    request_id_1 = _wait_for_cache_hit(url, timeout_s=hit_timeout_s, interval_s=2.0)

    apigw.flush_stage_cache(restApiId=api_id, stageName=stage_name)

    def _probe() -> str:
        _, body = _http_get_retry(url, timeout_s=10.0, interval_s=2.0)
        return json.loads(body)["requestId"]

    remaining_for_flush = max(10.0, 300.0 - (time.monotonic() - start_time) - 8.0)
    flush_timeout_s = min(60.0, remaining_for_flush)
    request_id_3 = _poll_until_new_value(_probe, request_id_1, timeout_s=flush_timeout_s, interval_s=2.0)
    assert request_id_3 != request_id_1, "FlushStageCache should force a freshly-evaluated response"


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_backend_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cache-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_backend_lambda(ctx) -> str:
    role_arn = _create_backend_role(ctx)
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-cache-fn-")
    code = _zip_bytes(_BACKEND_CODE)

    deadline = time.monotonic() + 60.0
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return resp["FunctionArn"]


def _allow_apigateway_invoke(ctx, function_arn: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    fn_name = function_arn.split(":")[-1]
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _http_get(url: str, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _http_get_retry(url: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> tuple[int, str]:
    deadline = time.monotonic() + timeout_s
    last: tuple[int, str] | None = None
    while time.monotonic() < deadline:
        status, body = _http_get(url, timeout=10.0)
        if status == 200:
            return status, body
        last = (status, body)
        time.sleep(interval_s)
    raise AssertionError(f"endpoint never returned 200 within {timeout_s}s; last={last!r}")


def _wait_for_cache_hit(url: str, timeout_s: float = 20.0, interval_s: float = 2.0) -> str:
    """Poll the endpoint until two consecutive calls return the same cached uuid.

    Enabling caching takes effect asynchronously, so the first calls may still reach the backend;
    the deadline includes the baseline fetch so the flush step keeps its share of the budget."""
    deadline = time.monotonic() + timeout_s
    status, body = _http_get_retry(url, timeout_s=10.0, interval_s=2.0)
    assert status == 200, f"expected 200, got {status}: {body}"
    baseline = json.loads(body)["requestId"]

    while time.monotonic() < deadline:
        status, body = _http_get_retry(url, timeout_s=10.0, interval_s=2.0)
        assert status == 200, f"expected 200, got {status}: {body}"
        candidate = json.loads(body)["requestId"]
        if candidate == baseline:
            return baseline
        baseline = candidate
        time.sleep(interval_s)
    raise AssertionError(f"cached response was never reused within {timeout_s}s of TTL")


def _poll_until_new_value(probe, old_value, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = old_value
    while time.monotonic() < deadline:
        last = probe()
        if last != old_value:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"value never changed from {old_value!r} within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
