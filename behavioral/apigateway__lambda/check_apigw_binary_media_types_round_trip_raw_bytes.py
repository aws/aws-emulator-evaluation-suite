"""apigw-binary-media-types-round-trip-raw-bytes."""

from __future__ import annotations

import base64
import hashlib
import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-binary-media-types-round-trip-raw-bytes"

GROUP = "data-format"

SERVICES = ["apigateway", "lambda"]


_CONTENT_TYPE = "application/octet-stream"

_HANDLER = """
import base64
import hashlib
import json
import os

BLOB = bytes.fromhex(os.environ["BLOB_HEX"])


def lambda_handler(event, context):
    method = (event.get("requestContext") or {}).get("httpMethod") or event.get(
        "httpMethod"
    )
    if method == "POST":
        raw = event.get("body") or ""
        if event.get("isBase64Encoded"):
            decoded = base64.b64decode(raw)
        else:
            decoded = raw.encode("utf-8", "replace")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "requestIsBase64": bool(event.get("isBase64Encoded")),
                    "sha256": hashlib.sha256(decoded).hexdigest(),
                    "length": len(decoded),
                }
            ),
        }
    return {
        "statusCode": 200,
        "isBase64Encoded": True,
        "headers": {"Content-Type": "application/octet-stream"},
        "body": base64.b64encode(BLOB).decode(),
    }
"""


def _wire(ctx, fn, api_id, root_id):
    """Attach GET+POST /blob to the Lambda proxy on an already-created REST API."""
    ag = ctx.client("apigateway")
    res_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="blob")[
        "id"
    ]
    for method in ("GET", "POST"):
        ag.put_method(
            restApiId=api_id,
            resourceId=res_id,
            httpMethod=method,
            authorizationType="NONE",
        )
        ag.put_integration(
            restApiId=api_id,
            resourceId=res_id,
            httpMethod=method,
            type="AWS_PROXY",
            integrationHttpMethod="POST",
            uri=(
                f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                f"{fn['arn']}/invocations"
            ),
        )
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
        statement_id=f"apigw-{api_id}",
    )
    _deploy_stage(ctx, api_id, "test")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With binaryMediaTypes set, a GET returns the exact bytes and a POSTed binary body reaches the
    integration base64-encoded with an intact sha256; on a twin API without it the same GET returns
    the base64 text."""
    # Deliberately NOT valid UTF-8: a latin-1/utf-8 round trip through a text path would
    # mangle these bytes, which is exactly the corruption being measured.
    blob = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) + b"\xff\xfe\xfd"
    fn = _create_lambda(ctx, _HANDLER, env={"BLOB_HEX": blob.hex()})

    binary_api, binary_root = _create_rest_api(
        ctx, kind="apigw-binary", binaryMediaTypes=[_CONTENT_TYPE]
    )
    text_api, text_root = _create_rest_api(ctx, kind="apigw-text")
    _wire(ctx, fn, binary_api, binary_root)
    _wire(ctx, fn, text_api, text_root)

    accept = {"Accept": _CONTENT_TYPE}

    # Response direction, binary-enabled API: exact bytes.
    _poll_http(
        _rest_invoke_url(ctx, binary_api, "test", "/blob"),
        accept=lambda s: s == 200,
        headers=accept,
        description="binary-enabled API GET /blob",
    )
    status, headers, body = _http_bytes(
        "GET", _rest_invoke_url(ctx, binary_api, "test", "/blob"), headers=accept
    )
    assert status == 200, f"binary API GET expected 200, got {status}: {body[:200]!r}"
    assert body == blob, (
        f"binary-enabled API should return the {len(blob)} raw bytes; got "
        f"{len(body)} bytes starting {body[:16]!r} (equal to the base64 text => "
        f"binaryMediaTypes/isBase64Encoded was ignored on the response)"
    )
    assert (headers.get("content-type") or "").startswith(_CONTENT_TYPE), (
        f"expected Content-Type {_CONTENT_TYPE}, got {headers.get('content-type')!r}"
    )

    # Response direction, plain API: the SAME handler output, but as base64 text.
    _poll_http(
        _rest_invoke_url(ctx, text_api, "test", "/blob"),
        accept=lambda s: s == 200,
        headers=accept,
        description="text API GET /blob",
    )
    t_status, _, t_body = _http_bytes(
        "GET", _rest_invoke_url(ctx, text_api, "test", "/blob"), headers=accept
    )
    assert t_status == 200, f"text API GET expected 200, got {t_status}: {t_body[:200]!r}"
    assert t_body == base64.b64encode(blob), (
        f"an API with NO binaryMediaTypes must hand back the handler's base64 text "
        f"unchanged; got {len(t_body)} bytes starting {t_body[:16]!r}"
    )
    assert t_body != body, (
        "both APIs returned identical bodies — binaryMediaTypes made no difference, so "
        "the setting is not being honoured in at least one direction"
    )

    # Request direction, binary-enabled API: the integration sees intact bytes.
    post_status, _, post_body = _poll_http(
        _rest_invoke_url(ctx, binary_api, "test", "/blob"),
        accept=lambda s: s == 200,
        method="POST",
        body=blob,
        headers={"Content-Type": _CONTENT_TYPE},
        description="binary-enabled API POST /blob",
    )
    assert post_status == 200, f"binary API POST expected 200, got {post_status}: {post_body}"
    payload = json.loads(post_body)
    assert payload.get("requestIsBase64") is True, (
        "a request body whose Content-Type is in binaryMediaTypes must reach the "
        f"integration with isBase64Encoded=true; event said {payload.get('requestIsBase64')!r}"
    )
    assert payload.get("length") == len(blob), (
        f"integration saw {payload.get('length')} bytes, sent {len(blob)}"
    )
    assert payload.get("sha256") == hashlib.sha256(blob).hexdigest(), (
        f"the POSTed bytes were corrupted in transit: integration sha256 "
        f"{payload.get('sha256')!r} != {hashlib.sha256(blob).hexdigest()!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on timeout. Propagation (IAM, stage deploy, log delivery) is
    always waited out this way — never with a bare time.sleep as the assertion.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _stays_absent(
    probe, predicate, *, window_s=25.0, interval_s=2.5, description="effect"
):
    """Assert predicate(probe()) stays FALSY for a whole bounded window.

    The negative-delivery shape: an effect that must NEVER appear is observed over a
    settle window, not with one racy read that could pass simply by being early.
    """
    deadline = time.monotonic() + window_s
    while True:
        last = probe()
        assert not predicate(last), (
            f"{description} appeared but must NOT have (delivery was suppressed "
            f"upstream). Observed: {last!r}"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _http(method, url, body=None, headers=None, timeout_s=20):
    """HTTP request via urllib (stdlib only). Returns (status, lower-cased headers, text).

    A 4xx/5xx is a RESULT, not an exception — negative checks assert on the status and
    body of the error response, so HTTPError is unwrapped rather than raised.
    """
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as e:
        return (
            e.code,
            {k.lower(): v for k, v in e.headers.items()},
            e.read().decode("utf-8", "replace"),
        )


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status) is true; return (status, headers, text).

    Stage/deployment/execute-api-DNS propagation is real and measured in seconds, so the
    first request through a freshly deployed stage is polled to a CONDITION with a bounded
    deadline. Connection-level errors (DNS/TLS still settling) are retried, not raised.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, "connection error")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} {url} never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:400]!r}"
    )


def _rest_invoke_url(ctx, api_id, stage, path):
    """The invoke URL of a DEPLOYED REST API stage, from ``ctx.rest_api_url``.

    Real AWS: ``https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>``; under an
    emulator, the ``/_aws/execute-api/<id>/<stage>/<path>`` route.
    """
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind="api", **extra):
    """Create a REGIONAL REST API (teardown registered) and return (api_id, root_resource_id)."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=_xname(ctx, kind),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xsvc_resource_tags(),
        **extra,
    )["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None, **extra):
    """CreateDeployment + CreateStage. Returns the deployment id.

    Deployment and stage are separate on purpose: several checks put two stages on ONE
    deployment to isolate a per-stage setting as the only variable.
    """
    ag = ctx.client("apigateway")
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    kwargs = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kwargs["variables"] = variables
    kwargs.update(extra)
    ag.create_stage(**kwargs)
    ctx.on_cleanup(
        lambda: ctx.client("apigateway").delete_stage(restApiId=api_id, stageName=stage)
    )
    return dep_id


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None, managed_policies=None):
    """Create an IAM role and register its (policies-first) teardown. Returns {name,arn}.

    IAM propagation is real: the caller must still tolerate the first use of a brand-new
    role failing (see _create_function_with_retry / the apigateway credentials retries).
    """
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} Active",
    )


def _delete_log_group(ctx, group: str) -> None:
    """Delete the function's log group; a function never invoked has none, so absence is done."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
):
    """Create a Lambda, RETRYING through the IAM role-propagation window, then wait Active.

    Registers the function's teardown plus its auto-created /aws/lambda/<name> log group
    (which survives function deletion and would otherwise leak).
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while True:
        try:
            resp = lam.create_function(**kwargs)
            # Registered first so it runs after the function delete: cleanup is LIFO.
            ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{name}"))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                if time.monotonic() >= deadline:
                    break
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
):
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM
    statement fragments like [{"Action": ["dynamodb:PutItem"], "Resource": arn}]); logs are
    always allowed. Role + function each register their own teardown. Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    """Grant apigateway.amazonaws.com lambda:InvokeFunction, scoped to source_arn."""
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e):
            raise


def _http_bytes(method, url, body=None, headers=None, timeout_s=20):
    """Like _http but returns the RAW response body bytes.

    Binary-media-type assertions must compare bytes: decoding to str would hide exactly
    the base64-vs-binary difference the check exists to measure.
    """
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read(),
            )
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
