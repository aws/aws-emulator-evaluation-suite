"""deep-apigatewayv2-3-stagesem-manual-stage-serves-deployment-snapshot."""

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

CHECK = "deep-apigatewayv2-3-stagesem-manual-stage-serves-deployment-snapshot"

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

#: Consecutive identical responses that count as "converged". One response can come from a node
#: that already picked up the new deployment while its neighbours have not.
_CONVERGED_RUN = 3


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A stage without autoDeploy keeps serving its deployment snapshot after an integration change.

    The autoDeploy twin converges on backend B; the manual stage returns A for 3x that latency and B
    only after an explicit CreateDeployment.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-stages.html
    """
    role_arn = _create_lambda_role(ctx, [])
    log_groups: list = []
    ctx.on_cleanup(lambda: _reap_log_groups(ctx, log_groups))
    marker_a = ctx.unique_name("sim2real-behav-snapA-")
    marker_b = ctx.unique_name("sim2real-behav-snapB-")
    fn_a = _create_lambda(ctx, role_arn, _HANDLER, log_groups, env={"MARKER": marker_a})
    fn_b = _create_lambda(ctx, role_arn, _HANDLER, log_groups, env={"MARKER": marker_b})

    account = _account_id(ctx)
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_name(ctx, "httpapi-snapshot"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*"
    _allow_apigw_invoke(ctx, fn_a["name"], source_arn)
    _allow_apigw_invoke(ctx, fn_b["name"], source_arn)

    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn_a["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /snap", Target=f"integrations/{integration_id}")

    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    first_deployment = agw.create_deployment(ApiId=api_id)["DeploymentId"]
    agw.create_stage(ApiId=api_id, StageName="pinned", DeploymentId=first_deployment)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="pinned")
    )

    auto_url = _invoke_url(ctx, api["ApiEndpoint"], "$default", "/snap")
    pinned_url = _invoke_url(ctx, api["ApiEndpoint"], "pinned", "/snap")

    # One 200 is not readiness (see _STABLE_S): both stages must serve A continuously first, so a
    # node still 404ing the brand-new stage cannot be mistaken for a snapshot violation below.
    _wait_stable(
        [(auto_url, None, (200, marker_a)), (pinned_url, None, (200, marker_a))],
        description="the autoDeploy and the pinned stage",
    )

    pinned_stage = agw.get_stage(ApiId=api_id, StageName="pinned")
    assert pinned_stage.get("AutoDeploy") is not True, (
        f"precondition: the pinned stage must not auto-deploy, got {pinned_stage.get('AutoDeploy')!r}"
    )
    assert pinned_stage["DeploymentId"] == first_deployment, (
        f"pinned stage should be bound to {first_deployment!r}, got {pinned_stage['DeploymentId']!r}"
    )
    auto_before = agw.get_stage(ApiId=api_id, StageName="$default").get("DeploymentId")

    agw.update_integration(ApiId=api_id, IntegrationId=integration_id, IntegrationUri=fn_b["arn"])
    changed_at = time.monotonic()

    # The twin's propagation latency calibrates the hold window and proves the change was published.
    pinned_samples: list = []
    first_b = None
    deadline = changed_at + 180.0
    while time.monotonic() < deadline:
        status, text = _get(auto_url)
        if status == 200 and text == marker_b:
            first_b = time.monotonic()
            break
        # Interleave the pinned stage so the snapshot is held even while the twin is converging.
        pinned_samples.append(_get(pinned_url))
        time.sleep(1.0)
    assert first_b is not None, (
        "the autoDeploy $default twin never served backend B within 180s of UpdateIntegration — "
        "the change was not auto-deployed, so the snapshot comparison below would prove nothing"
    )
    latency_s = first_b - changed_at
    _wait_for_run(auto_url, marker_b, _CONVERGED_RUN, timeout_s=120.0, label="$default (autoDeploy)")
    auto_after = agw.get_stage(ApiId=api_id, StageName="$default").get("DeploymentId")
    assert auto_after and auto_after != auto_before, (
        f"autoDeploy must have minted a new deployment for $default, DeploymentId stayed "
        f"{auto_before!r} -> {auto_after!r}"
    )

    # Hold: the pinned stage keeps serving A for 3x the measured latency (floored at 15s so the
    # window always takes several samples).
    window_s = max(3.0 * latency_s, 15.0)
    hold_until = time.monotonic() + window_s
    while True:
        pinned_samples.append(_get(pinned_url))
        if time.monotonic() >= hold_until:
            break
        time.sleep(1.5)
    wrong = [s for s in pinned_samples if s != (200, marker_a)]
    assert not wrong, (
        f"the non-autoDeploy stage must keep serving its deployment snapshot (backend A "
        f"{marker_a!r}) after the integration changed; within a {window_s:.1f}s hold (3x measured "
        f"autoDeploy latency {latency_s:.2f}s) it returned {wrong[:5]!r} of {len(pinned_samples)} "
        f"samples"
    )
    assert len(pinned_samples) >= 5, f"hold took only {len(pinned_samples)} samples"
    assert agw.get_stage(ApiId=api_id, StageName="pinned")["DeploymentId"] == first_deployment, (
        "the pinned stage's DeploymentId moved without an explicit deployment"
    )

    # Release: a second explicit CreateDeployment bound to the pinned stage.
    second_deployment = agw.create_deployment(ApiId=api_id, StageName="pinned")["DeploymentId"]
    assert second_deployment != first_deployment, "CreateDeployment returned the old id"
    _wait_for_run(pinned_url, marker_b, _CONVERGED_RUN, timeout_s=180.0, label="pinned (manual)")
    assert agw.get_stage(ApiId=api_id, StageName="pinned")["DeploymentId"] == second_deployment, (
        "after CreateDeployment(StageName=pinned) the stage must be bound to the new deployment"
    )


def _get(url):
    status, _, text = _http("GET", url)
    return (status, text)


def _wait_for_run(url, marker, run_len, *, timeout_s, label):
    """Poll until `run_len` CONSECUTIVE responses are (200, marker); RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    streak = 0
    last = None
    while time.monotonic() < deadline:
        try:
            last = _get(url)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, f"connection error: {exc}")
        streak = streak + 1 if last == (200, marker) else 0
        if streak >= run_len:
            return
        time.sleep(1.0)
    raise AssertionError(
        f"{label} ({url}) never served {marker!r} {run_len}x in a row within {timeout_s}s; "
        f"last {last!r}"
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


#: After a new stage/deployment first serves 200, individual nodes can keep answering 404 for
#: ~30s, so readiness is a continuous clean window longer than that tail.
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
    """Delete each /aws/lambda/<fn> group until it stays absent for 20s (bounded at 60s).

    delete_function leaves the group, and a buffered log flush can recreate it seconds later."""
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
    """Create a Lambda, retrying through the IAM role-propagation window, then wait for Active.
    Its name joins `log_groups`, whose reap net the caller registered BEFORE any function, so LIFO
    runs it after every delete_function."""
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
