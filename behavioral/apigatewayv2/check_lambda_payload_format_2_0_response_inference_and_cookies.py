"""lambda-payload-format-2-0-response-inference-and-cookies."""

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

CHECK = "lambda-payload-format-2-0-response-inference-and-cookies"

GROUP = "invoke"

SERVICES = ["apigatewayv2"]

#: One handler behind both integrations, branching only on the last path segment. The bare-JSON
#: branch returns NO statusCode, which format 2.0 must interpret and format 1.0 must not.
_HANDLER = """
import os


def lambda_handler(event, context):
    marker = os.environ["MARKER"]
    path = event.get("rawPath") or event.get("path") or ""
    leaf = path.rstrip("/").rsplit("/", 1)[-1]
    if leaf in ("bare2", "bare1"):
        return {"marker": marker, "shape": "bare-json", "leaf": leaf}
    if leaf == "cookies2":
        return {
            "statusCode": 200,
            "cookies": ["sc1=one; Path=/", "sc2=two; Path=/"],
            "headers": {"Content-Type": "text/plain"},
            "body": marker,
        }
    return {"statusCode": 500, "body": "unrouted leaf " + leaf}
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Format 2.0 infers a 200 JSON response from a bare-JSON Lambda return and expands ``cookies``
    into one set-cookie header each; the identical handler behind format 1.0 yields a 5xx instead.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """
    marker = ctx.unique_name("sim2real-behav-resp-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-respfmt"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    integrations = {}
    for version in ("1.0", "2.0"):
        integrations[version] = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            IntegrationMethod="POST",
            PayloadFormatVersion=version,
        )["IntegrationId"]
    for path, version in (("/bare2", "2.0"), ("/cookies2", "2.0"), ("/bare1", "1.0")):
        agw.create_route(
            ApiId=api_id,
            RouteKey=f"GET {path}",
            Target=f"integrations/{integrations[version]}",
        )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    # --- 2.0: bare JSON is inferred into a complete 200 response
    status, headers, text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", "/bare2"),
        accept=lambda s: s == 200,
        description="GET /bare2 on the PayloadFormatVersion=2.0 integration",
    )
    assert status == 200, (
        f"payload format 2.0 must infer statusCode 200 for a Lambda response carrying no "
        f"statusCode, got {status}: {text[:300]!r}"
    )
    # Containment, not equality: the header may carry parameters such as a charset suffix.
    content_type = _hdr(headers, "content-type") or ""
    assert "application/json" in content_type, (
        f"payload format 2.0 must infer content-type 'application/json' for an inferred response, "
        f"got {content_type!r}"
    )
    inferred = json.loads(text)
    assert inferred == {"marker": marker, "shape": "bare-json", "leaf": "bare2"}, (
        f"payload format 2.0 must use the handler's ENTIRE return value as the response body; "
        f"expected {{'marker': {marker!r}, 'shape': 'bare-json', 'leaf': 'bare2'}}, got "
        f"{inferred!r}"
    )
    assert "statusCode" not in inferred, (
        f"the inferred body must be the returned object itself, not an envelope echo: {inferred!r}"
    )

    # --- 2.0: a cookies list becomes one set-cookie header per entry
    status, headers, text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", "/cookies2"),
        accept=lambda s: s == 200,
        description="GET /cookies2 on the PayloadFormatVersion=2.0 integration",
    )
    assert status == 200, (
        f"expected 200 from the explicit 2.0 response envelope, got {status}: {text[:300]!r}"
    )
    assert text == marker, (
        f"expected the explicit 2.0 envelope's body {marker!r} verbatim, got {text[:300]!r}"
    )
    set_cookies = _hdr_all(headers, "set-cookie")
    assert len(set_cookies) == 2, (
        f"a 2.0 response cookies list of 2 entries must produce exactly 2 set-cookie response "
        f"headers, got {len(set_cookies)}: {set_cookies!r}"
    )
    assert sorted(set_cookies) == ["sc1=one; Path=/", "sc2=two; Path=/"], (
        f"each cookies entry must be emitted verbatim as its own set-cookie header; expected "
        f"['sc1=one; Path=/', 'sc2=two; Path=/'], got {sorted(set_cookies)!r}"
    )

    # --- 1.0 twin control: the SAME bare-JSON return gets no inference
    status, _, text = _poll_http(
        _invoke_url(ctx, api_endpoint, "$default", "/bare1"),
        # Any real answer from the route itself. A 404 here is the stage/route still propagating
        # (the two 2.0 legs above already proved this stage serves), never the assertion's subject.
        accept=lambda s: s is not None and s != 404,
        description="GET /bare1 on the PayloadFormatVersion=1.0 integration",
    )
    # Docs say 500 but a malformed proxy response is commonly 502, so accept any 5xx.
    assert 500 <= status <= 599, (
        f"payload format 1.0 makes NO assumptions about a Lambda response, so a return value with "
        f"no statusCode is a malformed integration response and must surface as a 5xx; got "
        f"{status} with body {text[:300]!r} (a 200 here means the target applied 2.0 response "
        f"inference to a 1.0 integration)"
    )
    assert marker not in text, (
        f"the un-inferred 1.0 response body must NOT leak the handler's payload to the client; "
        f"marker {marker!r} appeared in {text[:300]!r}"
    )


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _hdr(headers, name):
    """The first value of a response header, or None. `headers` is a list of (name, value)."""
    for key, value in headers:
        if key == name:
            return value
    return None


def _hdr_all(headers, name):
    """EVERY value of a repeated response header, in order. A dict would collapse set-cookie."""
    return [value for key, value in headers if key == name]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
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
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
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
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
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
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through the IAM
    role-propagation window, then wait for Active. Teardown registered for role, function and the
    auto-created /aws/lambda/<name> log group."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
