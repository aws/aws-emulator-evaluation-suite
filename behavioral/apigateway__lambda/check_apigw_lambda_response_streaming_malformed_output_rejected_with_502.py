"""apigw-lambda-response-streaming-malformed-output-rejected-with-502."""

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

CHECK = "apigw-lambda-response-streaming-malformed-output-rejected-with-502"
GROUP = "response-streaming"
SERVICES = ["apigateway", "lambda"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_OK_BODY = b"compliant-body"
_BAD_BODY = b'{"message": "Internal server error"}'

_OK_HANDLER_JS = """
exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {
  const metadata = { statusCode: 200 };
  responseStream = awslambda.HttpResponseStream.from(responseStream, metadata);
  responseStream.write("compliant-body");
  responseStream.end();
});
"""

# No JSON-metadata preamble and no 8-null-byte delimiter: the required
# response-streaming output format (metadata<DELIMITER>payload) is absent entirely.
_BAD_HANDLER_JS = """
exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {
  responseStream.write("no-metadata-preamble-at-all");
  responseStream.end();
});
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Stream-mode Lambda proxy integration whose function output has no JSON-metadata and
    delimiter preamble answers the client 502, while a compliant sibling integration succeeds.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/response-transfer-mode-lambda.html
    """
    lam = ctx.client("lambda")
    ag = ctx.client("apigateway")

    role_arn = _execution_role(ctx)
    ok_fn = ctx.unique_name("sim2real-behav-agwbad-ok-")
    bad_fn = ctx.unique_name("sim2real-behav-agwbad-bad-")
    _create_function(
        ctx, lam,
        FunctionName=ok_fn, Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": _OK_HANDLER_JS})},
        MemorySize=256, Timeout=30,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _create_function(
        ctx, lam,
        FunctionName=bad_fn, Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": _BAD_HANDLER_JS})},
        MemorySize=256, Timeout=30,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _wait_active(ctx, lam, ok_fn)
    _wait_active(ctx, lam, bad_fn)
    ok_arn = lam.get_function_configuration(FunctionName=ok_fn)["FunctionArn"]
    bad_arn = lam.get_function_configuration(FunctionName=bad_fn)["FunctionArn"]

    api_id, root_id = _create_rest_api(ctx, ag)
    ok_res = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="ok")["id"]
    bad_res = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="bad")["id"]

    _wire_stream_method(ctx, ag, api_id, ok_res, "ok", ok_fn, ok_arn)
    _wire_stream_method(ctx, ag, api_id, bad_res, "bad", bad_fn, bad_arn)
    _deploy_stage(ctx, ag, api_id, "test")

    ok_url = f"{ctx.rest_api_url(api_id, 'test')}/ok"
    bad_url = f"{ctx.rest_api_url(api_id, 'test')}/bad"

    # Poll the ok leg until it actually succeeds (a propagation 403/5xx is not a verdict), THEN
    # make a single request for the bad leg: by then the same deployment/propagation window has
    # settled, so the bad leg's first answer is already the real one.
    ok_status, _, ok_body = _poll_http(ctx, ok_url, accept=lambda s: s == 200)
    assert ok_status == 200, (
        f"the compliant sibling integration must still succeed; got {ok_status}: {ok_body[:300]!r}"
    )
    assert ok_body == _OK_BODY, (
        f"the compliant sibling must deliver its stream body unchanged; got {ok_body!r}"
    )

    bad_status, _, bad_body = _http("GET", bad_url, ctx.http_verify)
    assert bad_status == 502, (
        f"a Stream-mode integration whose function output has no JSON-metadata/delimiter "
        f"preamble must be answered 502 by API Gateway, got {bad_status}: {bad_body[:300]!r}"
    )
    assert bad_body == _BAD_BODY, (
        f"the 502 body must be API Gateway's own error JSON {_BAD_BODY!r}, got {bad_body!r}"
    )


def _wire_stream_method(ctx, ag, api_id, res_id, path_part, fn_name, fn_arn):
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
        ctx, fn_name,
        f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/GET/{path_part}",
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
    role_name = ctx.unique_name("sim2real-behav-agwbad-role-")
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
        raise TimeoutError(f"CreateFunction({name}): the run budget ended first; not graded")
    raise AssertionError(f"CreateFunction({name}) never succeeded within {timeout_s:.0f}s; last {last!r}")


def _wait_active(ctx, lam, name: str, cap_s: float = 90.0) -> None:
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        state = lam.get_function_configuration(FunctionName=name)["State"]
        if state == "Active":
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"function {name!r} never reached Active; the run budget ended first; not graded")
    raise AssertionError(f"function {name!r} never reached Active within {timeout_s:.0f}s")


def _create_rest_api(ctx, ag):
    name = ctx.unique_name("sim2real-behav-agwbad-api-")
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
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(method, url, verify, timeout_s=20):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(verify)) as resp:  # noqa: S310 - fixed http(s) scheme
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _poll_http(ctx, url, *, accept, cap_s=150.0, interval_s=2.0, method="GET"):
    """Poll the deployed stage until a response is reached; execute-api DNS/stage propagation
    is real, so the first requests after CreateStage are retried rather than treated as failures."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = (None, {}, b"")
    while True:
        try:
            last = _http(method, url, ctx.http_verify)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS still settling
            last = (None, {}, b"connection error")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{url}: the run budget ended first; not graded")
    raise AssertionError(f"{url} never answered within {timeout_s}s. Last: {last[0]} {last[2][:300]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
