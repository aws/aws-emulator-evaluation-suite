"""apigw-lambda-response-streaming-delivers-payload-past-the-10mb-rest-api-limit."""

from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-lambda-response-streaming-delivers-payload-past-the-10mb-rest-api-limit"
GROUP = "response-streaming"
SERVICES = ["apigateway", "lambda"]

# API Gateway's own REST API "API Payload Size" service quota is a fixed, non-adjustable
# 10 MB (10,485,760 bytes). A streamed response is documented to exceed it.
_REST_API_PAYLOAD_QUOTA = 10 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_CHUNK_COUNT = 11
_TOTAL_BYTES = _CHUNK_BYTES * _CHUNK_COUNT
_EXPECTED_BODY = b"A" * _TOTAL_BYTES

_HANDLER_JS = """
const CHUNK = "A".repeat(%d);
exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {
  const metadata = { statusCode: 200, headers: { "content-type": "text/plain" } };
  responseStream = awslambda.HttpResponseStream.from(responseStream, metadata);
  for (let i = 0; i < %d; i++) {
    responseStream.write(CHUNK);
  }
  responseStream.end();
});
""" % (_CHUNK_BYTES, _CHUNK_COUNT)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Stream-mode Lambda proxy integration delivers a response payload larger than API
    Gateway's own 10 MB REST API payload-size quota, byte-exact and in full.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/response-transfer-mode-lambda.html
    Reference: https://docs.aws.amazon.com/general/latest/gr/apigateway.html
    """
    assert _TOTAL_BYTES > _REST_API_PAYLOAD_QUOTA, (
        f"test payload {_TOTAL_BYTES} must itself exceed the {_REST_API_PAYLOAD_QUOTA}-byte quota"
    )

    lam = ctx.client("lambda")
    ag = ctx.client("apigateway")

    role_arn = _execution_role(ctx)
    fn = ctx.unique_name("sim2real-behav-agwbig-")
    _create_function(
        ctx, lam,
        FunctionName=fn, Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": _HANDLER_JS})},
        MemorySize=512, Timeout=60,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _wait_active(ctx, lam, fn)
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    api_id, root_id = _create_rest_api(ctx, ag)
    res_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="big")["id"]
    ag.put_method(restApiId=api_id, resourceId=res_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2021-11-15/functions/"
            f"{fn_arn}/response-streaming-invocations"
        ),
        responseTransferMode="STREAM",
    )
    _allow_apigw_invoke(
        ctx, fn,
        f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/GET/big",
    )
    _deploy_stage(ctx, ag, api_id, "test")

    url = f"{ctx.rest_api_url(api_id, 'test')}/big"
    status, _, body = _poll_http(
        ctx, url,
        accept=lambda s: s is not None and s not in (403, 500, 502, 503),
        timeout_s=180.0,
    )

    assert status == 200, f"a {_TOTAL_BYTES}-byte streamed response must succeed, got {status}: {body[:300]!r}"
    assert len(body) == _TOTAL_BYTES, (
        f"expected exactly {_TOTAL_BYTES} bytes (past the {_REST_API_PAYLOAD_QUOTA}-byte REST "
        f"API payload quota), got {len(body)} bytes"
    )
    assert body == _EXPECTED_BODY, (
        "the streamed body must reassemble byte-exact; it did not match the expected "
        f"{_TOTAL_BYTES}-byte all-'A' payload"
    )


def _make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _execution_role(ctx) -> str:
    """A bare Lambda execution role: trust only, no log permissions (the claim never reads logs)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-agwbig-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the role-propagation refusal. Raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"CreateFunction({name}) never succeeded: the run budget ended first; not graded")
    raise AssertionError(f"CreateFunction({name}) never succeeded within {timeout_s:.0f}s; last {last!r}")


def _wait_active(ctx, lam, name: str, timeout_s: float = 90.0) -> None:
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    while True:
        state = lam.get_function_configuration(FunctionName=name)["State"]
        if state == "Active":
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"function {name!r} never reached Active: the run budget ended first; not graded"
                )
            raise AssertionError(f"function {name!r} never reached Active, last state {state!r}")
        time.sleep(2)


def _create_rest_api(ctx, ag):
    name = ctx.unique_name("sim2real-behav-agwbig-api-")
    api_id = ag.create_rest_api(
        name=name,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _deploy_stage(ctx, ag, api_id, stage):
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=dep_id)
    ctx.on_cleanup(_teardown(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage), "NotFoundException"))


def _allow_apigw_invoke(ctx, fn_name, source_arn):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(method, url, timeout_s=60, *, verify=True):
    req = urllib.request.Request(url, method=method)
    context = _ssl_context(verify) if url.startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=context) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _poll_http(ctx, url, *, accept, timeout_s=150.0, interval_s=2.0, method="GET"):
    """Poll the deployed stage until a response is reached; execute-api DNS/stage propagation
    is real, so the first requests after CreateStage are retried rather than treated as failures,
    and a transient 403/5xx while the stage or invoke permission propagates is retried too."""
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    last = (None, {}, b"")
    while True:
        try:
            last = _http(method, url, verify=ctx.http_verify)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS still settling
            last = (None, {}, b"connection error")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{url} never answered: the run budget ended first; not graded")
    raise AssertionError(f"{url} never answered within {budgeted:.0f}s. Last: {last[0]} {last[2][:300]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
