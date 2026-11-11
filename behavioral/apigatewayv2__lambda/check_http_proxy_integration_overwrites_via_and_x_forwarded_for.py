"""http-proxy-integration-overwrites-via-and-x-forwarded-for."""

from __future__ import annotations

import ipaddress
import json
import ssl
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-proxy-integration-overwrites-via-and-x-forwarded-for"

GROUP = "http-proxy-header-handling"

SERVICES = ["apigatewayv2", "lambda"]

#: The origin echoes the headers it received, so only the backend can observe what actually
#: crossed the wire.
_ORIGIN_HANDLER = """
import json


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"headers": event.get("headers") or {}}),
    }
"""

_SPOOFED_VIA = "2.0 client-claimed-hop, 1.1 another-claimed-hop"
_SPOOFED_XFF = "203.0.113.9, 198.51.100.7"
_SPOOFED_HEADERS = {"Via": _SPOOFED_VIA, "X-Forwarded-For": _SPOOFED_XFF}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A client-supplied Via/X-Forwarded-For reaches a direct AWS_PROXY backend unmodified, but an
    HTTP_PROXY hop to the same backend overwrites Via and X-Forwarded-For with its own values,
    discarding what the client claimed.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html
    """
    fn = _create_lambda(ctx, _ORIGIN_HANDLER)
    agw = ctx.client("apigatewayv2")
    account = _account_id(ctx)

    # --- the origin API (an ordinary Lambda-backed HTTP API, reached directly and via the proxy)
    origin_api = agw.create_api(
        Name=_name(ctx, "httpapi-origin"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    origin_id, origin_endpoint = origin_api["ApiId"], origin_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=origin_id))
    origin_integration = agw.create_integration(
        ApiId=origin_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=origin_id,
        RouteKey="GET /echo",
        Target=f"integrations/{origin_integration}",
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{origin_id}/*/*"
    )
    agw.create_stage(
        ApiId=origin_id, StageName="$default", AutoDeploy=True, Tags=_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=origin_id, StageName="$default")
    )
    origin_url = _invoke_url(ctx, origin_endpoint, "$default", "/echo")

    # --- the front API: HTTP_PROXY to the origin, with NO authored header mapping at all —
    # any header change observed is the gateway's own unconditional behaviour, not a mapping.
    front_api = agw.create_api(
        Name=_name(ctx, "httpapi-front"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    front_id, front_endpoint = front_api["ApiId"], front_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=front_id))
    front_integration = agw.create_integration(
        ApiId=front_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=origin_url,
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=front_id, RouteKey="GET /front", Target=f"integrations/{front_integration}"
    )
    agw.create_stage(
        ApiId=front_id, StageName="$default", AutoDeploy=True, Tags=_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=front_id, StageName="$default")
    )
    front_url = _invoke_url(ctx, front_endpoint, "$default", "/front")

    # --- direct call: the client's Via/XFF reach the AWS_PROXY backend across ONE hop only
    direct_status, _, direct_text = _poll_http(
        origin_url,
        accept=lambda s: s == 200,
        headers=dict(_SPOOFED_HEADERS),
        description="the origin API serving GET /echo directly",
        verify=ctx.http_verify,
        budget_s=lambda want: _budget_s(ctx, want),
    )
    assert direct_status == 200, (
        f"the direct call to the origin must succeed before the proxied comparison means "
        f"anything, got {direct_status}: {direct_text[:300]!r}"
    )
    direct_headers = json.loads(direct_text)["headers"]
    assert direct_headers.get("via") == _SPOOFED_VIA, (
        f"a single AWS_PROXY hop with no intermediate HTTP_PROXY must deliver the client's own "
        f"Via unmodified; origin saw via={direct_headers.get('via')!r}"
    )
    assert direct_headers.get("x-forwarded-for", "").startswith(_SPOOFED_XFF + ", "), (
        f"a single hop must keep the client's X-Forwarded-For chain and only APPEND the real "
        f"peer; origin saw x-forwarded-for={direct_headers.get('x-forwarded-for')!r}"
    )

    # --- proxied call: the SAME client headers, to the SAME origin, through the front's
    # HTTP_PROXY integration — an extra hop that is the only thing that changed.
    proxied_status, _, proxied_text = _poll_http(
        front_url,
        accept=lambda s: s == 200,
        headers=dict(_SPOOFED_HEADERS),
        description="the front API proxying GET /front to the origin via HTTP_PROXY",
        verify=ctx.http_verify,
        budget_s=lambda want: _budget_s(ctx, want),
    )
    assert proxied_status == 200, (
        f"the proxied call must also succeed, so the header difference is attributable to the "
        f"extra hop and not a failure; got {proxied_status}: {proxied_text[:300]!r}"
    )
    proxied_headers = json.loads(proxied_text)["headers"]
    assert proxied_headers.get("via") == "HTTP/1.1 AmazonAPIGateway", (
        f"the HTTP_PROXY hop must overwrite Via with its own 'HTTP/1.1 AmazonAPIGateway', "
        f"discarding the client-claimed {_SPOOFED_VIA!r}; origin saw "
        f"via={proxied_headers.get('via')!r}"
    )
    proxied_xff = proxied_headers.get("x-forwarded-for")
    assert proxied_xff, (
        f"the HTTP_PROXY hop must send its own X-Forwarded-For to the origin; origin saw "
        f"x-forwarded-for={proxied_xff!r}"
    )
    assert _SPOOFED_XFF not in proxied_xff, (
        f"the HTTP_PROXY hop must overwrite X-Forwarded-For with its own observed peer, never "
        f"the client-claimed chain {_SPOOFED_XFF!r}; origin saw x-forwarded-for={proxied_xff!r}"
    )
    assert _is_ip_address(proxied_xff), (
        f"the overwritten X-Forwarded-For must be the single real peer address, not a chain; "
        f"origin saw x-forwarded-for={proxied_xff!r}"
    )


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _budget_s(ctx, want):
    """`want` seconds, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want if left is None else max(1.0, min(want, left - 10.0))


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition", budget_s=None
):
    """Poll probe() until predicate(result); return it. Raises TimeoutError on timeout."""
    if budget_s is not None:
        timeout_s = budget_s(timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20, *, verify=True):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(
            req, timeout=timeout_s, context=_ssl_context(verify)
        ) as resp:
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
    verify=True,
    budget_s=None,
):
    """Poll an invoke URL until accept(status); return (status, headers, text).

    Raises TimeoutError on timeout.
    """
    if budget_s is not None:
        timeout_s = budget_s(timeout_s)
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers, verify=verify)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
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


def _reap_log_group(ctx, name):
    """delete_function leaves /aws/lambda/<fn>, and a late log flush can RECREATE it after one
    delete, so the reap re-deletes until the group stays gone over a bounded window."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    quiet = 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and quiet < 3:
        try:
            logs.delete_log_group(logGroupName=group)
            quiet = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            quiet += 1
        time.sleep(2)
    if quiet < 3:
        raise RuntimeError(f"log group {group} kept reappearing")


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
        budget_s=lambda want: _budget_s(ctx, want),
    )
    # Registered before delete_function so LIFO runs the reap after it.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
        budget_s=lambda want: _budget_s(ctx, want),
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


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
