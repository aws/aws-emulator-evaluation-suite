"""flush-stage-authorizers-cache-forces-reinvoke."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "flush-stage-authorizers-cache-forces-reinvoke"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]

_AUTHORIZER_CODE = """
import time

def handler(event, context):
    return {
        "principalId": "sim2real-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": event.get("methodArn", "*")}
            ],
        },
        "context": {"marker": str(time.time_ns())},
    }
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FlushStageAuthorizersCache forces a cached Lambda TOKEN authorizer to run again within its
    TTL: two rapid calls see the same per-invocation marker, the first call after the flush
    sees a new one."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    region = ctx.region
    account_id = sts.get_caller_identity()["Account"]

    lambda_arn = _create_authorizer_lambda(ctx)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-authzcache-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="TOKEN",
        authorizerUri=f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=120,
    )["id"]

    source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/authorizers/{authorizer_id}"
    _allow_apigateway_invoke(ctx, lambda_arn, source_arn)

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"marker":"$context.authorizer.marker"}'},
    )

    stage_name = "sim"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    url = f"{ctx.rest_api_url(api_id, stage_name)}/"
    headers = {"Authorization": "allow-me"}

    status1, body1 = _http_get_retry(url, headers, timeout_s=90.0, interval_s=3.0)
    assert status1 == 200, f"expected 200, got {status1}: {body1}"
    marker1 = json.loads(body1)["marker"]

    status2, body2 = _http_get_retry(url, headers, timeout_s=20.0, interval_s=2.0)
    assert status2 == 200, f"expected 200, got {status2}: {body2}"
    marker2 = json.loads(body2)["marker"]
    assert marker2 == marker1, f"expected cached authorizer decision, got {marker2!r} != {marker1!r}"

    apigw.flush_stage_authorizers_cache(restApiId=api_id, stageName=stage_name)

    def _probe() -> str:
        _, body = _http_get_retry(url, headers, timeout_s=30.0, interval_s=2.0)
        return json.loads(body)["marker"]

    marker3 = _poll_until_new_value(_probe, marker1, timeout_s=60.0, interval_s=3.0)
    assert marker3 != marker1, "FlushStageAuthorizersCache should force authorizer re-invocation"


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_authorizer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-authz-role-")
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


def _create_authorizer_lambda(ctx) -> str:
    role_arn = _create_authorizer_role(ctx)
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-authz-fn-")
    code = _zip_bytes(_AUTHORIZER_CODE)

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


def _http_get(url: str, headers: dict, timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _http_get_retry(url: str, headers: dict, timeout_s: float = 60.0, interval_s: float = 3.0) -> tuple[int, str]:
    deadline = time.monotonic() + timeout_s
    last: tuple[int, str] | None = None
    while time.monotonic() < deadline:
        status, body = _http_get(url, headers, timeout=10.0)
        if status == 200:
            return status, body
        last = (status, body)
        time.sleep(interval_s)
    raise AssertionError(f"endpoint never returned 200 within {timeout_s}s; last={last!r}")


def _poll_until_new_value(probe, old_value, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = old_value
    while time.monotonic() < deadline:
        last = probe()
        if last != old_value:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"value never changed from {old_value!r} within {timeout_s}s; last={last!r}")


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
