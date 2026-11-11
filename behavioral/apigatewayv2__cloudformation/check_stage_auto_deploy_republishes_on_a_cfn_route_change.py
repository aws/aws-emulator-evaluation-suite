"""stage-auto-deploy-republishes-on-a-cfn-route-change."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-auto-deploy-republishes-on-a-cfn-route-change"

GROUP = "state-machine"

SERVICES = ["apigatewayv2", "cloudformation"]

DEPLOYMENTS = Path(__file__).parent / "deployments"

_TEMPLATE = DEPLOYMENTS / "http-api-autodeploy-route-change.yaml"

_FROZEN_STAGE = "frozen"
# The pinned stage's 404 is sampled over this fixed window, after the AutoDeploy stage already
# serves the new route.
_ABSENCE_WINDOW_S = 6.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A stack update adding a route is served by an AutoDeploy stage with a new DeploymentId and no
    explicit deployment, while a twin stage pinned to the old deployment keeps 404ing the new route
    until an explicit CreateDeployment publishes it there.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-stages.html
    """
    ctx.verify_account_safety()
    assert _TEMPLATE.is_file(), (
        f"the deploy artifact must exist on disk: expected a template at {_TEMPLATE}"
    )

    api_name = _xname(ctx, "httpapi-autodeploy")
    fn_name = _xname(ctx, "fn-echo")
    role_name = _xname(ctx, "role-lambda")
    stack = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "ApiName": api_name,
            "FunctionName": fn_name,
            "RoleName": role_name,
            "IncludeSecondRoute": "false",
        },
        timeout_s=_budget_s(ctx, 600.0),
    )
    api_id = stack["outputs"]["ApiIdOut"]
    assert stack["outputs"]["RouteSetOut"] == "v1", (
        f"the stack must be created declaring the v1-only route set, outputs say "
        f"{stack['outputs']!r}"
    )

    agw = ctx.client("apigatewayv2")
    auto_v1 = _v2_invoke_url(ctx, api_id, "$default", "/v1")
    auto_v2 = _v2_invoke_url(ctx, api_id, "$default", "/v2")

    # The deployed thing must actually work before anything else is measured.
    status, _, text = _poll_http(
        ctx, auto_v1,
        accept=lambda s: s == 200,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=1.5,
        description="GET /v1 on the AutoDeploy $default stage created by the stack",
    )
    assert status == 200, f"the stack's $default stage must serve GET /v1, got {status}: {text!r}"
    assert json.loads(text).get("routeKey") == "GET /v1", (
        f"the response must come from the v1 route's integration, got {text[:300]!r}"
    )
    pre_status, _, pre_text = _http("GET", auto_v2)
    assert pre_status == 404, (
        f"GET /v2 must not exist before the update, got {pre_status}: {pre_text[:300]!r}"
    )

    # The twin control, created OUT OF BAND so CloudFormation cannot advance it: same API, same
    # routes, pinned to an explicit deployment, AutoDeploy off.
    frozen_deployment = agw.create_deployment(ApiId=api_id)["DeploymentId"]
    agw.create_stage(
        ApiId=api_id,
        StageName=_FROZEN_STAGE,
        DeploymentId=frozen_deployment,
        AutoDeploy=False,
        Tags=_xsvc_resource_tags(),
    )
    # Registered AFTER the deploy so LIFO runs it BEFORE the stack delete.
    ctx.on_cleanup(lambda: _delete_stage_if_present(ctx, api_id, _FROZEN_STAGE))
    frozen_v1 = _v2_invoke_url(ctx, api_id, _FROZEN_STAGE, "/v1")
    frozen_v2 = _v2_invoke_url(ctx, api_id, _FROZEN_STAGE, "/v2")

    status, _, text = _poll_http(
        ctx, frozen_v1,
        accept=lambda s: s == 200,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=1.5,
        description=f"GET /v1 on the pinned {_FROZEN_STAGE} stage",
    )
    assert status == 200, (
        f"the pinned {_FROZEN_STAGE} stage must serve GET /v1 before the update, so its later "
        f"silence on /v2 is a snapshot boundary and not a dead stage; got {status}: {text!r}"
    )
    assert json.loads(text).get("routeKey") == "GET /v1", (
        f"the pinned stage's response must come from the v1 route, got {text[:300]!r}"
    )
    auto_deployment_before = agw.get_stage(ApiId=api_id, StageName="$default").get("DeploymentId")
    assert auto_deployment_before, (
        f"an AutoDeploy stage that is serving must report a DeploymentId; GetStage returned "
        f"{agw.get_stage(ApiId=api_id, StageName='$default')!r}"
    )

    # The single lever: the same template, one parameter moved.
    _update_cfn(
        ctx,
        stack["stack_name"],
        _TEMPLATE,
        parameters={
            "ApiName": api_name,
            "FunctionName": fn_name,
            "RoleName": role_name,
            "IncludeSecondRoute": "true",
        },
        timeout_s=_budget_s(ctx, 600.0),
    )
    routes = {r["RouteKey"] for r in agw.get_routes(ApiId=api_id).get("Items") or []}
    assert routes == {"GET /v1", "GET /v2"}, (
        f"after the update the API must declare both routes, GetRoutes reports {sorted(routes)}"
    )

    # Terminal read 1 — the AutoDeploy stage republished itself, measured at the endpoint.
    started = time.monotonic()
    status, _, text = _poll_http(
        ctx, auto_v2,
        accept=lambda s: s == 200,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=1.5,
        description=(
            "GET /v2 on the AutoDeploy $default stage after the stack update (auto-deploy "
            "propagation, which this check never triggers explicitly)"
        ),
    )
    propagation_s = max(time.monotonic() - started, 1.0)
    assert status == 200, (
        f"an AutoDeploy stage must serve a route added by a stack update with NO explicit "
        f"deployment, got {status}: {text[:300]!r}"
    )
    assert json.loads(text).get("routeKey") == "GET /v2", (
        f"the republished stage must answer through the NEW route, expected routeKey 'GET /v2', got "
        f"{text[:300]!r}"
    )
    status, _, text = _http("GET", auto_v1)
    assert status == 200 and json.loads(text).get("routeKey") == "GET /v1", (
        f"the update ADDED a route, so /v1 must keep serving on the republished stage; got "
        f"{status}: {text[:300]!r}"
    )
    auto_deployment_after = agw.get_stage(ApiId=api_id, StageName="$default").get("DeploymentId")
    assert auto_deployment_after and auto_deployment_after != auto_deployment_before, (
        f"AutoDeploy must have created a NEW deployment for the $default stage: DeploymentId was "
        f"{auto_deployment_before!r} before the update and is {auto_deployment_after!r} after — "
        f"this check issued no CreateDeployment for that stage"
    )

    # Terminal read 2 — the twin, in the same window: still the old snapshot.
    frozen_now = agw.get_stage(ApiId=api_id, StageName=_FROZEN_STAGE).get("DeploymentId")
    assert frozen_now == frozen_deployment, (
        f"the pinned stage must still point at the deployment it was created with "
        f"({frozen_deployment!r}), GetStage reports {frozen_now!r} — CloudFormation and AutoDeploy "
        f"must both have left it alone"
    )
    _assert_stays_absent(
        frozen_v2,
        expected_status=404,
        window_s=_ABSENCE_WINDOW_S,
        latency_s=propagation_s,
        because=(
            f"the {_FROZEN_STAGE} stage is pinned to a deployment taken before the route existed, "
            f"so GET /v2 must stay 404 there"
        ),
    )
    status, _, text = _http("GET", frozen_v1)
    assert status == 200 and json.loads(text).get("routeKey") == "GET /v1", (
        f"the pinned stage must still be SERVING while it withholds /v2 — an unreachable stage "
        f"would make the 404 above meaningless; GET /v1 gave {status}: {text[:300]!r}"
    )

    # Restore beat — one explicit deployment publishes the same route set to the pinned stage.
    explicit = agw.create_deployment(ApiId=api_id, StageName=_FROZEN_STAGE)["DeploymentId"]
    assert explicit != frozen_deployment, (
        f"CreateDeployment must mint a new deployment id, got {explicit!r} which equals the "
        f"pre-update one"
    )
    status, _, text = _poll_http(
        ctx, frozen_v2,
        accept=lambda s: s == 200,
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=1.5,
        description=(
            f"GET /v2 on the {_FROZEN_STAGE} stage once an explicit deployment published the "
            f"post-update route set to it"
        ),
    )
    assert status == 200, (
        f"after an explicit CreateDeployment the pinned stage must serve the added route, got "
        f"{status}: {text[:300]!r}"
    )
    assert json.loads(text).get("routeKey") == "GET /v2", (
        f"the pinned stage must now answer through the new route, expected routeKey 'GET /v2', got "
        f"{text[:300]!r}"
    )
    assert agw.get_stage(ApiId=api_id, StageName=_FROZEN_STAGE).get("DeploymentId") == explicit, (
        f"the pinned stage must now point at the deployment just created ({explicit!r}), GetStage "
        f"reports "
        f"{agw.get_stage(ApiId=api_id, StageName=_FROZEN_STAGE).get('DeploymentId')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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
    ctx,
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=180.0,
    interval_s=4.0,
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
    if _budget_spent(ctx):
        raise TimeoutError(f"{description} ({url}): the run budget ended first; not graded")
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _assert_stays_absent(url, *, expected_status, window_s, latency_s, because):
    """Assert a URL keeps answering `expected_status`, sampled across the whole window.

    The window follows the AutoDeploy stage serving the same route, so propagation has happened.
    """
    deadline = time.monotonic() + window_s
    samples = 0
    while True:
        status, _, text = _http("GET", url)
        assert status == expected_status, (
            f"{because}: got {status} (expected {expected_status}) within the {window_s:.1f}s "
            f"window (the AutoDeploy stage took {latency_s:.2f}s to serve the route). "
            f"Body: {text[:200]!r}"
        )
        samples += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    assert samples >= 2, (
        f"the absence window took {samples} sample(s), too few to be meaningful; expected >= 2 "
        f"over {window_s:.1f}s"
    )


def _v2_invoke_url(ctx, api_id, stage, path):
    """The invoke URL of an HTTP API stage, from ``ctx.api_url``."""
    p = path.lstrip("/")
    return f"{ctx.api_url(api_id, stage or '$default')}/{p}"


def _delete_stage_if_present(ctx, api_id, stage_name):
    """Teardown for the out-of-band stage; a stage already removed by the stack delete is fine."""
    try:
        ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _stack_status(ctx, stack_name):
    try:
        return ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0][
            "StackStatus"
        ]
    except ClientError:
        return "GONE"


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; on_cleanup owns the errors)."""
    ctx.client("cloudformation").delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _stack_parameters(parameters):
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()]


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=600.0
) -> dict[str, Any]:
    """Create a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE; register
    delete-stack-and-wait teardown. Returns {stack_name, stack_id, outputs:{k:v}}."""
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = _stack_parameters(parameters)
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=600.0))
    _poll_until(
        lambda: _stack_status(ctx, name),
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=1.5,
        description=f"CFN stack {name} reaching a terminal create state",
        ctx=ctx,
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"stack {name} ended in {stack['StackStatus']}: "
            f"{stack.get('StackStatusReason', '(no reason given)')}"
        )
    return {
        "stack_name": name,
        "stack_id": stack_id,
        "outputs": {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])},
    }


def _update_cfn(
    ctx, stack_name, template, *, parameters=None, capabilities=None, timeout_s=600.0
) -> dict:
    """Update a stack and wait for UPDATE_COMPLETE. RAISES on any other terminal state, so a
    rollback can never be mistaken for a successful update."""
    cfn = ctx.client("cloudformation")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = _stack_parameters(parameters)
    cfn.update_stack(**kwargs)
    _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
            "ROLLBACK_COMPLETE",
            "GONE",
        },
        timeout_s=timeout_s,
        interval_s=1.5,
        description=f"CFN stack {stack_name} reaching a terminal update state",
        ctx=ctx,
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "UPDATE_COMPLETE":
        raise AssertionError(
            f"stack {stack_name} update ended in {stack['StackStatus']}: "
            f"{stack.get('StackStatusReason', '(no reason given)')}"
        )
    return {"outputs": {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
