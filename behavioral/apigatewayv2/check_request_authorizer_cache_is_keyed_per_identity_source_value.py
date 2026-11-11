"""request-authorizer-cache-is-keyed-per-identity-source-value."""

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

CHECK = "request-authorizer-cache-is-keyed-per-identity-source-value"

GROUP = "authorizers"

SERVICES = ["apigatewayv2"]

#: One Lambda serves as both the authorizer and the backend, branching on the event shape: a
#: REQUEST-authorizer event carries "type": "REQUEST", a proxy event does not. Every authorizer
#: invocation writes one SQS message, which is the only way to COUNT invocations — the HTTP
#: response is identical whether the decision was computed or served from cache.
_HANDLER = """
import json
import os

import boto3


def lambda_handler(event, context):
    if event.get("type") == "REQUEST":
        boto3.client("sqs").send_message(
            QueueUrl=os.environ["QUEUE_URL"],
            MessageBody=json.dumps(
                {"identitySource": event.get("identitySource"), "marker": os.environ["MARKER"]}
            ),
        )
        return {"isAuthorized": True}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

_TTL_SECONDS = 300
# Each "no authorizer invocation" leg is sampled over this fixed window; the cache-miss leg that
# follows each one is its positive control.
_ABSENCE_WINDOW_S = 8.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A REQUEST authorizer's cache is keyed on the identity-source VALUE: counted via SQS, token A
    and a distinct token B each invoke it once, repeats of either invoke it zero more times, and
    ResetAuthorizersCache forces exactly one further invocation for A.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html"""
    marker = ctx.unique_name("sim2real-behav-authz-")
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=_name(ctx, "authzcount"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    fn = _create_lambda(
        ctx,
        _HANDLER,
        env={"QUEUE_URL": queue_url, "MARKER": marker},
        permissions=[{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn}],
    )

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-authzcache"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )
    authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        Name=_name(ctx, "reqauthz"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerResultTtlInSeconds=_TTL_SECONDS,
    )["AuthorizerId"]
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /guarded",
        Target=f"integrations/{integration_id}",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    _allow_apigw_invoke(
        ctx,
        fn["name"],
        f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*",
        statement_id="apigw-invoke",
    )

    url = _invoke_url(ctx, api_endpoint, "$default", "/guarded")
    token_settle = f"Bearer {marker}-settle"
    token_a = f"Bearer {marker}-alpha"
    token_b = f"Bearer {marker}-bravo"

    # Settle the deployment, then clear the queue so settling invocations are not counted. A
    # dedicated identity value is used, because ResetAuthorizersCache does not take effect
    # synchronously and leg 1 must measure a genuinely cold identity source.
    status, _, text = _poll_http(
        url,
        accept=lambda s: s == 200,
        headers={"Authorization": token_settle},
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=2.0,
        description="the authorizer-protected route serving its backend",
        ctx=ctx,
    )
    assert status == 200, (
        f"precondition: GET /guarded with an allow-decision authorizer should serve 200, got "
        f"{status}: {text[:300]!r}"
    )
    assert text == marker, (
        f"precondition: the backend marker {marker!r} should be the response body, got "
        f"{text[:300]!r}"
    )
    _drain_queue(sqs, queue_url)
    _reset_authorizers_cache(ctx, api_id)

    # Leg 1 — cold call for token A: exactly one authorizer invocation; its latency is reported
    # beside every absence window below.
    _get_ok(url, token_a, "token A cold call")
    started = time.monotonic()
    first = _poll_until(
        lambda: _drain_queue(sqs, queue_url),
        lambda n: n >= 1,
        timeout_s=_budget_s(ctx, 45.0),
        interval_s=2.0,
        description="the cold call's authorizer invocation arriving on the SQS side channel",
        ctx=ctx,
    )
    latency_s = time.monotonic() - started
    assert first == 1, (
        f"expected exactly 1 authorizer invocation for the cold call with token A, got {first}"
    )

    # Leg 2a — settle: the cold call's cache write may not be visible to the very next request.
    _settle_cache_write(sqs, queue_url, url, token_a, "token A")

    # Leg 2b — now that the cache write has settled, repeats must never invoke again, held for a
    # fixed window and confirmed by the queue's own reported depth.
    _get_ok(url, token_a, "token A repeat")
    _assert_no_invocations(
        sqs,
        queue_url,
        window_s=_ABSENCE_WINDOW_S,
        latency_s=latency_s,
        because="the cached decision for token A must be reused within its TTL",
    )

    # Leg 3 — a DIFFERENT identity value: a cache MISS, exactly one further invocation.
    _get_ok(url, token_b, "token B cold call")
    second = _poll_until(
        lambda: _drain_queue(sqs, queue_url),
        lambda n: n >= 1,
        timeout_s=_budget_s(ctx, 45.0),
        interval_s=2.0,
        description="token B's authorizer invocation (a distinct identity source value)",
        ctx=ctx,
    )
    assert second == 1, (
        f"a second, DIFFERENT Authorization value must miss the cache and invoke the authorizer "
        f"exactly once, got {second} invocation(s) — 0 means the target served token B the decision "
        f"it computed for token A"
    )
    _settle_cache_write(sqs, queue_url, url, token_b, "token B")
    body_b = _get_ok(url, token_b, "token B repeat")
    assert body_b == marker, f"token B must reach the same backend, got {body_b[:200]!r}"
    assert _drain_queue(sqs, queue_url) == 0, (
        "token B's settled repeat must be served from cache and must not leave a stray "
        "authorizer invocation for leg 4 to trip over"
    )

    # Leg 4 — both keys now cached side by side: neither repeat invokes the authorizer. A
    # single-slot cache would have evicted A when B arrived and fails here.
    _get_ok(url, token_a, "token A after B was cached")
    _assert_no_invocations(
        sqs,
        queue_url,
        window_s=_ABSENCE_WINDOW_S,
        latency_s=latency_s,
        because=(
            "both identity values must hold their own cache entry, so neither repeat may "
            "re-invoke the authorizer"
        ),
    )

    # Leg 5 — the flush restores invocation: exactly one, for the identical request that was
    # cached a moment ago.
    _reset_authorizers_cache(ctx, api_id)

    def _probe_after_reset():
        _get_ok(url, token_a, "token A after ResetAuthorizersCache")
        return _drain_queue(sqs, queue_url)

    after_reset = _poll_until(
        _probe_after_reset,
        lambda n: n >= 1,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=2.0,
        description=(
            "an authorizer invocation after ResetAuthorizersCache (the flush is not instantaneous "
            "across every node serving the stage, so the request is replayed)"
        ),
        ctx=ctx,
    )
    assert after_reset == 1, (
        f"expected exactly 1 authorizer invocation for the first request after "
        f"ResetAuthorizersCache, got {after_reset}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _reset_authorizers_cache(ctx, api_id):
    ctx.client("apigatewayv2").reset_authorizers_cache(ApiId=api_id, StageName="$default")


def _drain_queue(sqs, queue_url) -> int:
    """Receive-and-delete every visible message; return how many. The count IS the assertion."""
    total = 0
    for _ in range(6):
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        total += len(messages)
    return total


def _settle_cache_write(sqs, queue_url, url, token, label):
    """Retry until a probe is served from cache, since a cold call's cache write can take a couple of
    seconds to become readable; tightly capped so a target with no caching cannot pass."""
    deadline = time.monotonic() + 10.0
    settled_invocations = 0
    while True:
        _get_ok(url, token, f"{label} settle probe")
        n = _drain_queue(sqs, queue_url)
        if n == 0:
            return
        settled_invocations += n
        assert settled_invocations <= 2, (
            f"{label}'s cached decision should settle within a couple of requests after its cold "
            f"call, but {settled_invocations} further invocation(s) landed before any repeat was "
            f"served from cache -- this looks like no caching at all, not a settle race"
        )
        assert time.monotonic() < deadline, (
            f"repeats of {label} never stopped invoking the authorizer within 10s of the cold call"
        )
        time.sleep(1.5)


def _assert_no_invocations(sqs, queue_url, *, window_s, latency_s, because):
    """Hold "no authorizer invocation" for a fixed window, reported beside the cold latency.

    Sampled repeatedly rather than waited out once: a target with no cache at all fails on the
    FIRST sample instead of only after however long a fixed sleep happened to be. The queue's own
    reported depth is the second, independent observable.
    """
    deadline = time.monotonic() + window_s
    samples = 0
    while True:
        count = _drain_queue(sqs, queue_url)
        assert count == 0, (
            f"{because}: {count} authorizer invocation(s) arrived within the {window_s:.1f}s "
            f"window (the cold call's invocation arrived in {latency_s:.2f}s)"
        )
        samples += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(min(2.0, max(0.5, deadline - time.monotonic())))
    assert samples >= 3, (
        f"the absence window took {samples} sample(s), too few to be meaningful; expected >= 3 "
        f"over {window_s:.1f}s"
    )
    depth = int(
        sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
    )
    assert depth == 0, (
        f"{because}: the side-channel queue reports ApproximateNumberOfMessages == {depth}, "
        f"expected 0"
    )


def _get_ok(url, token, label) -> str:
    """GET url with `token`; assert 200 and return the body. Every leg must stay authorized —
    a leg that silently started failing would otherwise read as "the authorizer did not run"."""
    status, _, text = _http("GET", url, headers={"Authorization": token})
    assert status == 200, (
        f"{label}: expected 200 from the authorizer-protected route, got {status}: {text[:300]!r}"
    )
    return text


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition", ctx=None):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    timeout_s=180.0,
    interval_s=4.0,
    description="invoke URL",
    ctx=None,
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
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description} ({url}): the run budget ended first; not graded")
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
