"""deep-apigatewayv2-3-stagesem-stage-variable-target-without-invoke-permission-rejected."""

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

CHECK = "deep-apigatewayv2-3-stagesem-stage-variable-target-without-invoke-permission-rejected"

GROUP = "stage-deploy"

SERVICES = ["apigatewayv2"]

_HANDLER = """
import json
import os

import boto3


def lambda_handler(event, context):
    rc = event.get("requestContext") or {}
    qs = event.get("queryStringParameters") or {}
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["QUEUE_URL"],
        MessageBody=json.dumps({
            "marker": os.environ["MARKER"],
            "version": event.get("version"),
            "routeKey": event.get("routeKey"),
            "stage": rc.get("stage"),
            "stageVariables": event.get("stageVariables"),
            "nonce": qs.get("n"),
        }),
    )
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

_INTERNAL_ERROR = {"message": "Internal Server Error"}


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A stage whose `${stageVariables.fn}` names a Lambda without an API Gateway invoke permission
    gets 500 and never invokes it, while a sibling stage on the same deployment keeps serving;
    granting the permission alone makes the refused stage serve its own backend.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-stages.stage-variables.html
    """
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=_name(ctx, "svperm"), tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn}]
    )
    log_groups: list = []
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, log_groups))
    marker_ok = ctx.unique_name("sim2real-behav-svok-")
    marker_no = ctx.unique_name("sim2real-behav-svno-")
    fn_ok = _create_lambda(ctx, role_arn, _HANDLER, log_groups, env={"QUEUE_URL": queue_url, "MARKER": marker_ok})
    fn_no = _create_lambda(ctx, role_arn, _HANDLER, log_groups, env={"QUEUE_URL": queue_url, "MARKER": marker_no})

    account = _account_id(ctx)
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-svperm"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=f"arn:aws:lambda:{ctx.region}:{account}:function:${{stageVariables.fn}}",
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /who", Target=f"integrations/{integration_id}")
    deployment_id = agw.create_deployment(ApiId=api_id)["DeploymentId"]
    bindings = {"granted": fn_ok["name"], "ungranted": fn_no["name"]}
    for stage, fn_name in bindings.items():
        agw.create_stage(
            ApiId=api_id,
            StageName=stage,
            DeploymentId=deployment_id,
            StageVariables={"fn": fn_name},
        )
        ctx.on_cleanup(
            lambda s=stage: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=s)
        )

    source_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*"
    # Only the "granted" stage's function trusts API Gateway.
    _allow_apigw_invoke(ctx, fn_ok["name"], source_arn)

    granted_url = _invoke_url(ctx, api["ApiEndpoint"], "granted", "/who")
    ungranted_url = _invoke_url(ctx, api["ApiEndpoint"], "ungranted", "/who")

    # Positive control first: the shared integration/route/deployment works end to end.
    _, _, text = _poll_http(
        granted_url,
        accept=lambda s: s == 200,
        description="the permitted stage serving through ${stageVariables.fn}",
    )
    assert text == marker_ok, f"granted stage must serve {marker_ok!r}, got {text[:300]!r}"
    # One 200 is not readiness (see _STABLE_S): a node still 404ing the new stage must not be read
    # as the refusal (or as its absence).
    _wait_stable(
        [(granted_url, None, (200, marker_ok)), (ungranted_url, None, (500, None))],
        description="the granted and the ungranted stage",
    )

    # The broken stage: refused, with the exact HTTP API body.
    nonce_no = ctx.unique_name("n-ungranted-")
    status, _, text = _http("GET", f"{ungranted_url}?n={nonce_no}")
    assert status == 500, (
        f"a stage variable naming a Lambda with no apigateway invoke permission must be refused "
        f"with 500, got {status}: {text[:300]!r}"
    )
    assert json.loads(text) == _INTERNAL_ERROR, (
        f"refusal body must be exactly {_INTERNAL_ERROR!r}, got {text[:300]!r}"
    )

    # Absence is proven by a barrier, not a sleep: the permitted twin's request, sent AFTER the
    # refused one, must arrive on the side channel with no refused invocation ahead of it.
    nonce_ok = ctx.unique_name("n-granted-")
    status, _, text = _http("GET", f"{granted_url}?n={nonce_ok}")
    assert status == 200 and text == marker_ok, (
        f"granted twin must keep serving {marker_ok!r} beside the refused stage, got "
        f"{status}: {text[:300]!r}"
    )
    received: list = []
    _poll_until(
        lambda: received.extend(_drain(sqs, queue_url)) or [m.get("nonce") for m in received],
        lambda nonces: nonce_ok in nonces,
        timeout_s=60.0,
        interval_s=1.0,
        description="the permitted twin's correlated invocation reaching the side channel",
    )
    leaked = [m for m in received if m.get("marker") == marker_no]
    assert not leaked, (
        f"the ungranted Lambda was invoked although API Gateway had no permission to call it: "
        f"{leaked!r}"
    )
    # A few more refused requests, each followed by a twin barrier: the refusal is not a one-off.
    for i in range(3):
        status, _, text = _http("GET", f"{ungranted_url}?n={nonce_no}-{i}")
        assert status == 500, f"refused request {i} returned {status}: {text[:300]!r}"
        barrier = ctx.unique_name(f"n-barrier{i}-")
        _http("GET", f"{granted_url}?n={barrier}")
        _poll_until(
            lambda: received.extend(_drain(sqs, queue_url)) or [m.get("nonce") for m in received],
            lambda nonces, b=barrier: b in nonces,
            timeout_s=60.0,
            interval_s=1.0,
            description=f"barrier {i} on the permitted twin",
        )
    leaked = [m for m in received if m.get("marker") == marker_no]
    assert not leaked, f"the ungranted Lambda was invoked: {leaked!r}"

    # Repair exactly the one broken thing — the resource policy — and nothing else.
    _allow_apigw_invoke(ctx, fn_no["name"], source_arn)
    _, _, text = _poll_http(
        ungranted_url,
        accept=lambda s: s == 200,
        description="the previously refused stage serving once its target grants invoke",
    )
    assert text == marker_no, (
        f"after the permission is granted the stage must be served by its OWN target "
        f"{marker_no!r}, got {text[:300]!r}"
    )
    after = _poll_until(
        lambda: [m for m in _drain(sqs, queue_url) if m.get("marker") == marker_no],
        lambda ms: len(ms) >= 1,
        timeout_s=60.0,
        interval_s=1.0,
        description="the repaired target's invocation reaching the side channel",
    )
    assert after[0]["stageVariables"] == {"fn": fn_no["name"]}, (
        f"the repaired target must see its own stage's variables, got {after[0]['stageVariables']!r}"
    )
    assert after[0]["stage"] == "ungranted", f"stage seen was {after[0]['stage']!r}"



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


#: After a new stage/deployment first serves 200, individual nodes can answer 404 for ~30s more,
#: so readiness is a continuous clean window longer than that tail, not one 200.
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
    """Delete each /aws/lambda/<fn> group until it stays absent for 20s (bounded at 60s): a buffered
    log flush can recreate a group seconds after delete_function. RAISES if one keeps reappearing."""
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
    """Create a Lambda, retrying through IAM role propagation, then wait for Active. The name joins
    `log_groups`, whose reap the caller registered first so it runs after every delete_function."""
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
