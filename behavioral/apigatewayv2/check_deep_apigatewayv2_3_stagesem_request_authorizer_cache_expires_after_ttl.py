"""deep-apigatewayv2-3-stagesem-request-authorizer-cache-expires-after-ttl."""

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

CHECK = "deep-apigatewayv2-3-stagesem-request-authorizer-cache-expires-after-ttl"

GROUP = "authorizers"

SERVICES = ["apigatewayv2"]

#: One Lambda is both authorizer and backend. Each authorizer invocation writes one SQS message
#: tagged with its routeKey: the HTTP response is identical whether the decision was cached or not.
_HANDLER = """
import json
import os

import boto3


def lambda_handler(event, context):
    if event.get("type") == "REQUEST":
        boto3.client("sqs").send_message(
            QueueUrl=os.environ["QUEUE_URL"],
            MessageBody=json.dumps({
                "routeKey": event.get("routeKey"),
                "identitySource": event.get("identitySource"),
            }),
        )
        return {"isAuthorized": True}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

_TTL_S = 20
_TTL_ROUTE = "GET /ttl"
_ZERO_ROUTE = "GET /nottl"


# timing:real-time — ttl: 20 s https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A REQUEST authorizer with a 20 s TTL is invoked once cold, not inside the TTL, once after it.

    Its TTL=0 twin on the same Lambda and identity source is invoked on every request and barriers
    each absence; invocations are counted on an SQS side channel.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
    """
    marker = ctx.unique_name("sim2real-behav-ttl-")
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=_name(ctx, "ttlcount"), tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn}]
    )
    log_groups: list = []
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, log_groups))
    fn = _create_lambda(ctx, role_arn, _HANDLER, log_groups, env={"QUEUE_URL": queue_url, "MARKER": marker})

    account = _account_id(ctx)
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-authzttl"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*")
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"
    )
    authorizers = {}
    for route, ttl in ((_TTL_ROUTE, _TTL_S), (_ZERO_ROUTE, 0)):
        authorizers[route] = agw.create_authorizer(
            ApiId=api_id,
            Name=_name(ctx, f"authz{ttl}"),
            AuthorizerType="REQUEST",
            AuthorizerUri=authorizer_uri,
            AuthorizerPayloadFormatVersion="2.0",
            EnableSimpleResponses=True,
            IdentitySource=["$request.header.Authorization"],
            AuthorizerResultTtlInSeconds=ttl,
        )
        assert authorizers[route]["AuthorizerResultTtlInSeconds"] == ttl, (
            f"authorizer for {route} echoed TTL {authorizers[route]['AuthorizerResultTtlInSeconds']!r}"
        )
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    for route, authz in authorizers.items():
        agw.create_route(
            ApiId=api_id,
            RouteKey=route,
            Target=f"integrations/{integration_id}",
            AuthorizationType="CUSTOM",
            AuthorizerId=authz["AuthorizerId"],
        )
    # One explicit deployment after both routes exist: with AutoDeploy=True a node can still 404
    # the second route after several consecutive 200s.
    deployment_id = agw.create_deployment(ApiId=api_id)["DeploymentId"]
    agw.create_stage(ApiId=api_id, StageName="$default", DeploymentId=deployment_id)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    ttl_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/ttl")
    zero_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/nottl")
    token_settle = f"Bearer {marker}-settle"
    token_ttl = f"Bearer {marker}-ttl"
    token_zero = f"Bearer {marker}-zero"

    # Settle the deployment with a dedicated token on both routes, then clear the side channel.
    # One 200 is not readiness (see _STABLE_S): both routes must serve continuously first.
    _wait_stable(
        [(u, {"Authorization": token_settle}, (200, marker)) for u in (ttl_url, zero_url)],
        description="the two authorizer-protected routes",
    )
    _poll_until(
        lambda: _counts(_drain(sqs, queue_url)),
        lambda c: c == {},
        timeout_s=90.0,
        interval_s=1.0,
        description="the side channel draining empty after deployment settle",
    )

    def _zero_barrier(label):
        """One TTL=0 request; wait for its own invocation; return (counts seen, latency_s)."""
        sent = time.monotonic()
        _get_ok(zero_url, token_zero, label)
        seen: dict = {}

        def _probe():
            for k, v in _counts(_drain(sqs, queue_url)).items():
                seen[k] = seen.get(k, 0) + v
            return dict(seen)

        _poll_until(
            _probe,
            lambda c: c.get(_ZERO_ROUTE, 0) >= 1,
            timeout_s=45.0,
            interval_s=0.5,
            description=f"{label}: the TTL=0 authorizer's invocation on the side channel",
        )
        return seen, time.monotonic() - sent

    # Leg 1 — TTL=0 twin: every request invokes, exactly once each.
    latencies = []
    for i in range(3):
        seen, lat = _zero_barrier(f"TTL=0 request {i}")
        latencies.append(lat)
        assert seen == {_ZERO_ROUTE: 1}, (
            f"TTL=0 request {i} (same identity source as the previous one) must invoke its "
            f"authorizer exactly once and nothing else, side channel saw {seen!r}"
        )
    latency_s = max(latencies)
    guard_s = max(3.0, 2.0 * latency_s)

    # Leg 2 — TTL route, cold: exactly one invocation; the TTL is anchored on the request send time.
    anchor_sent = time.monotonic()
    _get_ok(ttl_url, token_ttl, "TTL cold call")
    anchor_done = time.monotonic()
    cold = _poll_until(
        lambda: _counts(_drain(sqs, queue_url)),
        lambda c: c.get(_TTL_ROUTE, 0) >= 1,
        timeout_s=45.0,
        interval_s=0.5,
        description="the TTL authorizer's cold invocation on the side channel",
    )
    assert cold == {_TTL_ROUTE: 1}, f"cold call must invoke exactly once, side channel saw {cold!r}"
    # A just-written cache entry may not be readable by the very next request; any such settle
    # invocation re-anchors the TTL to its request.
    anchor_sent, anchor_done = _settle(
        sqs, queue_url, ttl_url, token_ttl, anchor_sent, anchor_done, _zero_barrier
    )

    # Leg 3 — inside the TTL: zero invocations, each sample barriered by the TTL=0 twin.
    inside_end = anchor_sent + _TTL_S - guard_s
    inside_samples = 0
    while time.monotonic() < inside_end:
        _get_ok(ttl_url, token_ttl, f"inside-TTL repeat {inside_samples}")
        seen, _ = _zero_barrier(f"inside-TTL barrier {inside_samples}")
        assert seen == {_ZERO_ROUTE: 1}, (
            f"inside the {_TTL_S}s TTL (sample {inside_samples}, "
            f"{time.monotonic() - anchor_sent:.1f}s after the caching request) the TTL authorizer "
            f"must not be invoked while the TTL=0 twin is invoked exactly once; saw {seen!r}"
        )
        inside_samples += 1
    assert inside_samples >= 3, (
        f"only {inside_samples} inside-TTL samples fitted in the window (guard {guard_s:.1f}s from "
        f"measured latency {latency_s:.2f}s) — too few to be meaningful"
    )

    # Leg 4 — let the TTL elapse (with margin past the moment the entry was certainly written),
    # keeping the TTL=0 twin under load meanwhile: it still invokes on every request.
    expired_at = anchor_done + _TTL_S + guard_s
    gap = 0
    while time.monotonic() < expired_at:
        seen, _ = _zero_barrier(f"TTL-gap twin request {gap}")
        assert seen == {_ZERO_ROUTE: 1}, f"TTL-gap twin request {gap}: side channel saw {seen!r}"
        gap += 1
        time.sleep(min(1.0, max(0.0, expired_at - time.monotonic())))

    # Leg 5 — after expiry: the first request re-invokes, exactly once; then it is cached again.
    expiry_hits = 0
    attempts = 0
    deadline = expired_at + _TTL_S
    while expiry_hits == 0:
        assert time.monotonic() < deadline, (
            f"no TTL-authorizer invocation within {_TTL_S}s past its {_TTL_S}s TTL "
            f"({attempts} post-expiry request(s)) — the cached decision never expired"
        )
        _get_ok(ttl_url, token_ttl, f"post-TTL request {attempts}")
        seen, _ = _zero_barrier(f"post-TTL barrier {attempts}")
        attempts += 1
        expiry_hits = seen.get(_TTL_ROUTE, 0)
        assert seen.get(_ZERO_ROUTE) == 1, f"post-TTL barrier: twin saw {seen!r}"
    assert expiry_hits == 1, (
        f"the first request after the TTL elapsed must invoke the authorizer exactly once, got "
        f"{expiry_hits} (after {attempts} post-expiry request(s))"
    )
    _settle(sqs, queue_url, ttl_url, token_ttl, 0.0, 0.0, _zero_barrier)
    _get_ok(ttl_url, token_ttl, "re-cached repeat")
    seen, _ = _zero_barrier("re-cached barrier")
    assert seen == {_ZERO_ROUTE: 1}, (
        f"after the post-expiry invocation the decision must be cached again; saw {seen!r}"
    )


def _counts(messages) -> dict:
    out: dict = {}
    for m in messages:
        out[m.get("routeKey")] = out.get(m.get("routeKey"), 0) + 1
    return out


def _settle(sqs, queue_url, url, token, anchor_sent, anchor_done, barrier):
    """Retry until a repeat is served from cache, barriered by the TTL=0 twin; at most 2 extra
    invocations, so a target with NO caching cannot pass by exhausting the cap. Returns the
    (sent, done) times of the request that last wrote the cache entry."""
    extra = 0
    while True:
        sent = time.monotonic()
        _get_ok(url, token, "settle probe")
        done = time.monotonic()
        seen, _ = barrier("settle barrier")
        n = seen.get(_TTL_ROUTE, 0)
        if n == 0:
            return anchor_sent, anchor_done
        extra += n
        anchor_sent, anchor_done = sent, done
        assert extra <= 2, (
            f"{extra} further invocations landed before any repeat was served from cache — this "
            f"looks like no caching at all, not a cache-write settle race"
        )


_STALE_NODE_404 = (404, '{"message":"Not Found"}')


def _get_ok(url, token, label) -> str:
    """GET with `token`; RAISE unless 200. A stale node's 404 Not Found is retried, bounded.

    A route-level 404 never reaches the authorizer, so a retry cannot add to the counts.
    """
    for attempt in range(6):
        status, _, text = _http("GET", url, headers={"Authorization": token})
        if (status, text) != _STALE_NODE_404:
            break
        time.sleep(1.0)
    if status != 200:
        raise AssertionError(f"{label}: expected 200, got {status}: {text[:300]!r} (after {attempt} stale-node 404 retries)")  # noqa: E501
    return text


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _drain(sqs, queue_url) -> list:
    """Receive-and-delete every visible message; return their parsed bodies."""
    out = []
    for _ in range(6):
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            out.append(json.loads(msg["Body"]))
    return out


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


def _poll_http(url, *, accept, headers=None, timeout_s=120.0, interval_s=3.0, description="url"):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http("GET", url, headers=headers)
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


#: After a new deployment first serves 200, individual nodes can answer 404 for about 30 s more,
#: so readiness is a continuous clean window longer than that tail.
_STABLE_S = 40.0


def _wait_stable(probes, *, window_s=_STABLE_S, timeout_s=200.0, description="routes"):
    """probes: [(url, headers, (status, body-or-None))]. Poll until EVERY probe has returned its
    expected (status, body) continuously for window_s; any deviation restarts the window.
    RAISES on timeout, quoting the last deviation."""
    deadline = time.monotonic() + timeout_s
    clean_since = None
    last_bad = None
    while True:
        now = time.monotonic()
        ok = True
        for url, headers, (want_status, want_body) in probes:
            try:
                status, _, text = _http("GET", url, headers=headers)
            except OSError as exc:  # execute-api DNS/TLS still settling
                status, text = None, f"connection error: {exc}"
            if status != want_status or (want_body is not None and text != want_body):
                ok = False
                last_bad = (url, status, text[:200])
        if not ok:
            clean_since = None
        elif clean_since is None:
            clean_since = now
        elif now - clean_since >= window_s:
            return
        assert time.monotonic() < deadline, (
            f"{description} never served their expected responses continuously for {window_s}s "
            f"within {timeout_s}s; last deviation {last_bad!r}"
        )
        time.sleep(0.5)


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_lambda_role(ctx, extra_statements):
    iam = ctx.client("iam")
    role_name = _name(ctx, "role-lambda")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            *extra_statements,
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return resp["Role"]["Arn"]


def _reap_log_groups(ctx, names):
    """Delete every /aws/lambda/<fn> group until each stays absent for 20 s (bounded at 60 s).

    delete_function leaves the group, and a buffered flush can recreate it after a delete.
    """
    _leaks: list = []
    logs = ctx.client("logs")
    groups = [f"/aws/lambda/{n}" for n in names]
    absent_since = {g: None for g in groups}
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        for g in groups:
            try:
                logs.delete_log_group(logGroupName=g)
                absent_since[g] = None
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
                if absent_since[g] is None:
                    absent_since[g] = now
        if all(t is not None and now - t >= 20.0 for t in absent_since.values()):
            if _leaks:
                raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                    (e for _, e in _leaks if e is not None), None
                )
            return
        time.sleep(2.0)
    for g, t in absent_since.items():
        if t is None or time.monotonic() - t < 20.0:
            _leaks.append((f"log group {g} kept reappearing after delete", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _create_lambda(ctx, role_arn, handler_code, log_groups, env=None, timeout=30):
    """Create a Lambda through the IAM role-propagation window, then wait for Active.

    Its name joins `log_groups`, whose reap the caller registered first so LIFO runs it last.
    """
    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    log_groups.append(name)
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
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
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
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
