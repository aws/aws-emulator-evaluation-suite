"""canary-deployment-traffic-shift-and-promotion."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "canary-deployment-traffic-shift-and-promotion"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id

def _mock_method(ag, api_id, resource_id, http_method, response_template):
    """A fully wired MOCK method: 200 request template + 200 integration response."""
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE",
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200",
        selectionPattern="", responseTemplates={"application/json": response_template},
    )

def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - fixed http(s) scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())

def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=120.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A REST API deployment becomes servable on its stage asynchronously, so the first
    touch of a freshly (re-)deployed stage polls to a condition with a bounded
    deadline rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=({status}, {text!r})"
            )
        time.sleep(interval_s)

def _served(text):
    """(snapshot, release) served by the stage, or (None, None) if unparseable."""
    try:
        data = json.loads(text)
    except ValueError:
        return None, None
    return data.get("snapshot"), data.get("release")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A 100% canary stage serves the canary deployment with its stageVariableOverrides, 0% serves the
    base deployment again, and a copy patch from /canarySettings/deploymentId promotes the canary."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "release")
    template = ('{"snapshot":"%s",'
                '"release":"$util.escapeJavaScript($stageVariables.release)"}')
    _mock_method(ag, api_id, resource_id, "GET", template % "v1")

    base_deployment = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=base_deployment,
        variables={"release": "base"},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    url = _apigw_url(ctx, api_id, stage, "/release")
    _poll_http(
        url, lambda s, h, t: _served(t) == ("v1", "base"),
        description=f"GET {url} to serve the base deployment (snapshot v1, release=base)",
    )

    # Snapshot a changed template as a CANARY on the same stage, taking 100% of traffic
    # and overriding the `release` stage variable for canary requests only.
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": template % "v2"},
    )
    canary_deployment = ag.create_deployment(
        restApiId=api_id, stageName=stage,
        canarySettings={
            "percentTraffic": 100.0,
            "stageVariableOverrides": {"release": "canary"},
            "useStageCache": False,
        },
    )["id"]
    stage_now = ag.get_stage(restApiId=api_id, stageName=stage)
    assert stage_now["deploymentId"] == base_deployment, (
        f"attaching a canary must not move the stage's own deploymentId: expected "
        f"{base_deployment!r}, got {stage_now.get('deploymentId')!r}"
    )
    canary = stage_now.get("canarySettings") or {}
    assert canary.get("deploymentId") == canary_deployment, (
        f"expected canarySettings.deploymentId={canary_deployment!r}, got {canary!r}"
    )
    assert canary.get("percentTraffic") == 100.0, (
        f"expected canarySettings.percentTraffic=100.0, got {canary.get('percentTraffic')!r}"
    )
    assert (canary.get("stageVariableOverrides") or {}).get("release") == "canary", (
        f"expected the canary stage-variable override to round-trip, got {canary!r}"
    )

    _poll_http(
        url, lambda s, h, t: _served(t) == ("v2", "canary"),
        description=(
            f"GET {url} to be served by the 100% canary deployment "
            f"{canary_deployment!r} with release=canary applied"
        ),
    )

    # 0% canary: every request must fall back to the base deployment, and the canary's
    # stage-variable override must NOT apply to base traffic.
    ag.update_stage(
        restApiId=api_id, stageName=stage,
        patchOperations=[{"op": "replace", "path": "/canarySettings/percentTraffic",
                          "value": "0.0"}],
    )
    _poll_http(
        url, lambda s, h, t: _served(t) == ("v1", "base"),
        description=(
            f"GET {url} to fall back to the base deployment with release=base once "
            f"percentTraffic is 0.0"
        ),
    )

    # Promote: copy the canary deployment id onto the stage and drop canarySettings.
    ag.update_stage(
        restApiId=api_id, stageName=stage,
        patchOperations=[
            {"op": "copy", "from": "/canarySettings/deploymentId",
             "path": "/deploymentId"},
            {"op": "remove", "path": "/canarySettings"},
        ],
    )
    promoted = ag.get_stage(restApiId=api_id, stageName=stage)
    assert promoted["deploymentId"] == canary_deployment, (
        f"expected the copy patch to promote {canary_deployment!r} onto the stage, "
        f"got deploymentId={promoted.get('deploymentId')!r}"
    )
    assert not promoted.get("canarySettings"), (
        f"expected the remove patch to drop canarySettings, got "
        f"{promoted.get('canarySettings')!r}"
    )
    _poll_http(
        url, lambda s, h, t: _served(t) == ("v2", "base"),
        description=(
            f"GET {url} to serve the promoted snapshot v2 with the stage's own "
            f"release=base variable (no canary override left)"
        ),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
