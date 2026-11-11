"""create-stage-and-deployment."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

CHECK = "create-stage-and-deployment"
GROUP = 'routing'
SERVICES = ['apigatewayv2', 'apigateway']

# A URLError (nothing listening) is tagged with this marker so an absent data plane reads as a
# fidelity failure, not a network error; an HTTPError is not, since something did answer.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

def _http(method, url, body=None, headers=None):
    """Send one HTTP request; return (status, headers, body)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()
    except urllib.error.URLError as e:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: nothing answered at the HTTP API endpoint {url} ({e.reason}) -- the "
            "execute-api data plane is absent, which is a fidelity failure and not an environment error"
        ) from e


def _poll_http(url, want, timeout_s=90):
    """Poll until `want`; a new invoke host may not resolve yet, so an unreachable endpoint is
    retried, and if nothing ever answered the last unreachable error is RAISED at the deadline."""
    status, body = None, ""
    unreachable = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url)
        except (AssertionError, OSError) as exc:
            unreachable = exc
            time.sleep(3)
            continue
        if status == want:
            return status, body
        time.sleep(3)
    if status is None and unreachable is not None:
        raise unreachable
    return status, body


def _invoke_url(ctx, api_endpoint, path, stage):
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage)}/{p}"


def _mock_backend(ctx, body: str) -> str:
    """The invoke URL of a REST API stage the check owns whose MOCK integration answers GET / with
    200 and ``body``: a backend on the target itself, so the proxy leg never leaves it."""
    ag = ctx.client("apigateway")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=TAGS,
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, rest_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=rest_id)["items"] if r["path"] == "/")
    ag.put_method(restApiId=rest_id, resourceId=root, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": body},
    )
    ag.create_deployment(restApiId=rest_id, stageName="backend")
    return ctx.rest_api_url(rest_id, "backend")


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    """DeleteRestApi is throttled hard per account, so retry within a bounded budget and say so on
    stderr if the API survives, since teardown exceptions are swallowed."""
    import sys

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from exc
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


@tags(
    "axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane",
    "dp:endpoint", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A stage created with an explicit DeploymentId serves traffic with no further
    CreateDeployment, and a $default AutoDeploy stage serves with no explicit deployment at all.
    """
    # The upstream MOCK stage is read directly first so a failure there is not blamed on the stages.
    token = ctx.unique_name("sim2real-behav-upstream-")
    upstream = _mock_backend(ctx, token)
    pre_status, pre_body = _poll_http(upstream, 200)
    assert pre_status == 200 and pre_body == token, (
        f"precondition: the upstream MOCK stage should serve its token, got {pre_status}: {pre_body!r}"
    )

    agw = ctx.client("apigatewayv2")
    _api = agw.create_api(Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=_api["ApiId"]))
    api_id = _api["ApiId"]
    integ = agw.create_integration(ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationUri=upstream, IntegrationMethod="GET", PayloadFormatVersion="1.0")
    agw.create_route(
        ApiId=api_id, RouteKey="GET /items", Target=f"integrations/{integ['IntegrationId']}"
    )

    # Positive control: proves the API, route, integration and endpoint are live.
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    got_default = agw.get_stage(ApiId=api_id, StageName="$default")
    assert got_default.get("AutoDeploy") is True, (
        f"$default stage AutoDeploy not set: {got_default.get('AutoDeploy')}"
    )
    status, body = _poll_http(_invoke_url(ctx, _api["ApiEndpoint"], "/items", "$default"), 200)
    assert status == 200, (
        f"precondition: $default AutoDeploy stage should serve, got {status}: {body}"
    )

    # GetStage echoing the id is not proof of routing, so the stage is also invoked over HTTP.
    dep = agw.create_deployment(ApiId=api_id)
    dep_id = dep["DeploymentId"]
    assert dep_id, "CreateDeployment returned no DeploymentId"

    stage_name = f"s{ctx.unique_name('sim2real-behav-')[-8:]}"
    agw.create_stage(ApiId=api_id, StageName=stage_name, DeploymentId=dep_id)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName=stage_name))
    got = agw.get_stage(ApiId=api_id, StageName=stage_name)
    assert got["DeploymentId"] == dep_id, (
        f"stage deploymentId mismatch: {got.get('DeploymentId')} != {dep_id}"
    )

    status, body = _poll_http(_invoke_url(ctx, _api["ApiEndpoint"], "/items", stage_name), 200)
    assert status == 200, (
        f"stage created with DeploymentId={dep_id} at creation time did not serve "
        f"traffic, got {status}: {body} (a target that only bookkeeps the id "
        f"without wiring routing would 404 here)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
