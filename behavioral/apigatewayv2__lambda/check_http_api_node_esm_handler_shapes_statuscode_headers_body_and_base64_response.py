"""http-api-node-esm-handler-shapes-statuscode-headers-body-and-base64-response."""
from __future__ import annotations

import json
import ssl
import time
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "http-api-node-esm-handler-shapes-statuscode-headers-body-and-base64-response"
GROUP = "data-format"
SERVICES = ["apigatewayv2", "lambda"]

_TAGS = {"sim2real:managed": "true"}

# An ESM handler (`export const handler`), loaded from a bare `.mjs` file with no package.json
# and no bundling: the runtime treats a `.mjs` extension as a module regardless of "type".
_HANDLER_MJS = r"""
export const handler = async (event) => {
  const q = event.queryStringParameters || {};
  if (q.mode === "binary") {
    const bytes = Buffer.from("binary-ok-" + (q.tag || ""), "utf-8");
    return {
      statusCode: 200,
      headers: { "content-type": "application/octet-stream" },
      body: bytes.toString("base64"),
      isBase64Encoded: true,
    };
  }
  return {
    statusCode: 201,
    headers: { "x-node-esm": "yes" },
    body: JSON.stringify({
      method: event.requestContext.http.method,
      path: event.rawPath,
      tag: q.tag || null,
    }),
    isBase64Encoded: false,
  };
};
"""


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _get(url, verify=True):
    """GET, returning (status, headers-lowercased, text); an error status is a result."""
    ctx_ssl = _ssl_context(verify) if urllib.parse.urlsplit(url).scheme == "https" else None
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx_ssl) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, headers, exc.read().decode("utf-8", "replace")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP API AWS_PROXY (payload v2) integration lets a Node.js ESM Lambda handler shape the
    full HTTP response: a custom statusCode and header, a JSON body, and a base64 binary body
    decoded from isBase64Encoded.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    agw = ctx.client("apigatewayv2")

    role_name = ctx.unique_name("sim2real-httpapiesm-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                                Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    basic = f"arn:{role_arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic),
                             "NoSuchEntity"))

    fn_name = ctx.unique_name("sim2real-httpapiesm-fn-")
    group = f"/aws/lambda/{fn_name}"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.mjs", _HANDLER_MJS)
    create_timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + create_timeout_s
    while True:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=10, MemorySize=256, Tags=_TAGS,
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or \
                    "assumed" not in str(exc):
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateFunction never succeeded: the run budget ended first; not graded"
                    ) from exc
                raise
            time.sleep(2)

    def _reap_log_group() -> None:
        logs = ctx.client("logs")
        deadline2 = time.monotonic() + 45
        absent = 0
        while absent < 3:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 3:
                assert time.monotonic() < deadline2, "lambda log group never settled absent"
                time.sleep(5)

    ctx.on_cleanup(_reap_log_group)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    active_timeout_s = _budget_s(ctx, 120.0)
    try:
        lam.get_waiter("function_active_v2").wait(
            FunctionName=fn_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(active_timeout_s // 2))},
        )
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"function {fn_name!r} never reached Active: the run budget ended first; not graded"
            )
        raise

    created_api = agw.create_api(Name=ctx.unique_name("sim2real-httpapiesm-api-"),
                                 ProtocolType="HTTP", Tags=_TAGS)
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(_teardown(lambda: agw.delete_api(ApiId=api_id), "NotFoundException"))
    source_arn = f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*"
    lam.add_permission(FunctionName=fn_name, StatementId="apigw-invoke",
                       Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
                       SourceArn=source_arn)

    integration_id = agw.create_integration(
        ApiId=api_id, IntegrationType="AWS_PROXY", IntegrationUri=fn_arn,
        IntegrationMethod="POST", PayloadFormatVersion="2.0")["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /echo", Target=f"integrations/{integration_id}")
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(_teardown(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"),
                             "NotFoundException"))

    tag = ctx.unique_name("tag")
    base_url = f"{ctx.stage_url(api_endpoint, '$default')}/echo"

    def _poll_200(url):
        timeout_s = _budget_s(ctx, 150.0)
        deadline2 = time.monotonic() + timeout_s
        last = None
        while True:
            try:
                last = _get(url, verify=ctx.http_verify)
            except OSError as exc:
                last = (0, {}, repr(exc))
            if last[0] in (200, 201):
                return last
            if time.monotonic() >= deadline2:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        f"GET {url} never answered 200/201: the run budget ended first; not graded"
                    )
                raise AssertionError(
                    f"GET {url} never answered 200/201 within {timeout_s:.0f}s; last {last!r}"
                )
            time.sleep(2)

    status, headers, text = _poll_200(f"{base_url}?tag={tag}")
    assert status == 201, f"expected statusCode 201 from the handler, got {status}: {text[:200]!r}"
    assert headers.get("x-node-esm") == "yes", (
        f"expected header x-node-esm: yes from the handler's headers map, got {headers!r}"
    )
    body = json.loads(text)
    assert body == {"method": "GET", "path": "/echo", "tag": tag}, (
        f"unexpected echoed body {body!r}"
    )

    status2, headers2, text2 = _poll_200(f"{base_url}?mode=binary&tag={tag}")
    assert status2 == 200, f"expected statusCode 200 from the binary branch, got {status2}"
    assert headers2.get("content-type") == "application/octet-stream", (
        f"expected content-type application/octet-stream, got {headers2.get('content-type')!r}"
    )
    # API Gateway decodes an isBase64Encoded=true body before it reaches the wire, so the client
    # receives the raw bytes directly, not the base64 text the handler returned.
    assert text2 == f"binary-ok-{tag}", (
        f"isBase64Encoded response body did not arrive as the handler's decoded bytes: got {text2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
