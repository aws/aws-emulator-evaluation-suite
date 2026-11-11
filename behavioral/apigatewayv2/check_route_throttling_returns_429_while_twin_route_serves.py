"""route-throttling-returns-429-while-twin-route-serves."""

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

CHECK = "route-throttling-returns-429-while-twin-route-serves"

GROUP = "stage-deploy"

SERVICES = ["apigatewayv2"]

_HANDLER = """
import os


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

#: 1 rps with a burst of 1 against a _BURST-request burst (served at roughly 10/s) is far enough
#: over the limit to shed some requests without depending on an exact count.
_RATE_LIMIT = 1.0
_BURST_LIMIT = 1
_BURST = 24


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
    """A per-route throttle sheds part of a burst with 429 before the integration runs, while an
    interleaved burst on a twin route of the same stage sheds none; DeleteRouteSettings stops it.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-throttling.html
    """
    marker = ctx.unique_name("sim2real-behav-thr-")
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-throttle"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for path in ("/limited", "/twin"):
        agw.create_route(
            ApiId=api_id, RouteKey=f"GET {path}", Target=f"integrations/{integration_id}"
        )
    agw.create_stage(
        ApiId=api_id,
        StageName="$default",
        AutoDeploy=True,
        # Generous default so the TWIN route is limited only by the account-level ceiling, and the
        # only difference between the two routes is the per-route override below.
        DefaultRouteSettings={"ThrottlingRateLimit": 500.0, "ThrottlingBurstLimit": 200},
        RouteSettings={
            "GET /limited": {
                "ThrottlingRateLimit": _RATE_LIMIT,
                "ThrottlingBurstLimit": _BURST_LIMIT,
            }
        },
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    )

    limited_url = _invoke_url(ctx, api_endpoint, "$default", "/limited")
    twin_url = _invoke_url(ctx, api_endpoint, "$default", "/twin")

    stored = agw.get_stage(ApiId=api_id, StageName="$default").get("RouteSettings") or {}
    assert set(stored) == {"GET /limited"}, (
        f"the throttle must be stored against 'GET /limited' ONLY, so the twin route is a valid "
        f"control; GetStage reports RouteSettings for {sorted(stored)}"
    )

    for url, label in ((twin_url, "GET /twin"), (limited_url, "GET /limited")):
        status, _, text = _poll_http(
            url,
            accept=lambda s: s == 200,
            interval_s=3.0,
            description=f"{label} serving its backend before any burst",
        )
        assert status == 200, f"precondition: {label} should serve 200, got {status}: {text[:200]!r}"
        assert text == marker, (
            f"precondition: {label} should return this check's backend marker {marker!r}, got "
            f"{text[:200]!r}"
        )
    # A new AutoDeploy stage reaches every gateway node asynchronously: one 200 does not mean
    # every node serves the route yet. Wait until a run of requests to both routes all serve.
    _poll_until(
        lambda: [
            (label, status, text[:60])
            for _ in range(5)
            for url, label in ((twin_url, "GET /twin"), (limited_url, "GET /limited"))
            for status, _, text in [_http("GET", url)]
            if not (status == 200 and text == marker)
        ],
        lambda misses: not misses,
        timeout_s=150.0,
        interval_s=5.0,
        description="both routes serving the backend on every request of a slow run",
    )

    # Interleaved so both routes see the same rate in the same instant. Throttles are best-effort
    # targets, not guaranteed ceilings, so only ">= 1 throttled" is asserted, not a count.
    limited, twin = _interleaved_burst(limited_url, twin_url, _BURST)
    limited_429 = [s for s, _ in limited if s == 429]
    twin_429 = [s for s, _ in twin if s == 429]
    assert len(limited_429) >= 1, (
        f"a route limited to {_RATE_LIMIT} rps / burst {_BURST_LIMIT} must shed part of a "
        f"{_BURST}-request burst with 429; got statuses {[s for s, _ in limited]}"
    )
    assert not twin_429, (
        f"the throttle is per-ROUTE: the twin route (default settings, same stage, same "
        f"integration) must shed nothing in the same instant, got "
        f"{len(twin_429)} 429s out of {_BURST}: {[s for s, _ in twin]}"
    )
    throttled_bodies = [body for s, body in limited if s == 429]
    assert all("too many requests" in b.lower() for b in throttled_bodies), (
        f"expected every throttled response to carry the 'Too Many Requests' envelope, got "
        f"{throttled_bodies[:3]!r}"
    )
    assert all(marker not in b for b in throttled_bodies), (
        f"a throttled request must be shed by the gateway BEFORE the integration runs, so its "
        f"body must not contain the backend marker {marker!r}; got {throttled_bodies[:3]!r}"
    )
    served = [(s, b) for s, b in limited if s != 429]
    assert served, (
        f"the throttled route must still serve part of the burst — a route that answers 429 to "
        f"EVERY request is not throttling, it is broken; got {[s for s, _ in limited]}"
    )
    assert all(s == 200 and b == marker for s, b in served), (
        f"every non-throttled request on the limited route must be a normal 200 from the backend, "
        f"got {[(s, b[:60]) for s, b in served if not (s == 200 and b == marker)]!r}"
    )

    # Bounded retry: route settings on a live stage propagate asynchronously.
    agw.delete_route_settings(ApiId=api_id, StageName="$default", RouteKey="GET /limited")
    after = agw.get_stage(ApiId=api_id, StageName="$default").get("RouteSettings") or {}
    assert "GET /limited" not in after, (
        f"DeleteRouteSettings must remove the 'GET /limited' override, GetStage still reports "
        f"{sorted(after)}"
    )
    _poll_until(
        lambda: [s for s, _ in _interleaved_burst(limited_url, twin_url, _BURST)[0] if s == 429],
        lambda throttled: not throttled,
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            "the same burst against GET /limited shedding NOTHING once its route override is "
            "deleted (route-settings propagation on a live AutoDeploy stage)"
        ),
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


def _interleaved_burst(url_a, url_b, n):
    """Fire n requests at each URL, strictly alternating, as fast as the connections allow.

    Returns (results_a, results_b), each a list of (status, body). Interleaving is what makes the
    second URL a control group *in the same instant* rather than a later comparison.
    """
    results_a, results_b = [], []
    for _ in range(n):
        status, _, body = _http("GET", url_a)
        results_a.append((status, body))
        status, _, body = _http("GET", url_b)
        results_b.append((status, body))
    return results_a, results_b


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
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
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


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Lambda creates its log group on first invocation only, so it can be absent."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

