"""apigw-stage-variable-selects-a-different-backend-per-stage-from-one-deployment."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-stage-variable-selects-a-different-backend-per-stage-from-one-deployment"
GROUP = 'deployments-stages'
SERVICES = ['apigateway']


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so a throttle can
    be unrelated to the claim."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _create_api(ctx, ag, scenario):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    A REST API's only handle is a server-minted id,
    so the name, the description AND the tag all carry the sim2real marker."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": scenario},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=150.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A deployment, and a stage-variable update, become visible on the data plane
    asynchronously, so every first touch polls to a condition with a bounded deadline
    rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Two stages created from the SAME deployment substitute ${stageVariables.target} into
    the integration URI at request time, so each stage reaches a DIFFERENT backend and
    returns a different body — and changing the variable re-points a stage with no redeploy."""
    ag = ctx.client("apigateway")

    markers = {part: f"sim2real-{part}-{_unique_token()}"
               for part in ("blue", "green", "third")}

    # ---- backend API: three routes, three distinct bodies ----
    backend_id = _create_api(ctx, ag, "stage-variable-backends")
    for part, marker in markers.items():
        resource_id = _child(ctx, ag, backend_id, part)
        _retry_throttled(lambda rid=resource_id: ag.put_method(
            restApiId=backend_id, resourceId=rid, httpMethod="GET",
            authorizationType="NONE",
        ))
        _retry_throttled(lambda rid=resource_id: ag.put_integration(
            restApiId=backend_id, resourceId=rid, httpMethod="GET", type="MOCK",
            requestTemplates={"application/json": '{"statusCode":200}'},
        ))
        _retry_throttled(lambda rid=resource_id: ag.put_method_response(
            restApiId=backend_id, resourceId=rid, httpMethod="GET", statusCode="200",
        ))
        _retry_throttled(lambda rid=resource_id, m=marker: ag.put_integration_response(
            restApiId=backend_id, resourceId=rid, httpMethod="GET", statusCode="200",
            selectionPattern="",
            responseTemplates={"application/json": '{"target":"%s"}' % m},
        ))
    backend_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=backend_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=backend_id, stageName="b", deploymentId=backend_deployment,
        tags={"sim2real": "stage-variable-backends"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=backend_id, stageName="b")))
    backend_base = _apigw_url(ctx, backend_id, "b").rstrip("/")

    # Precondition, not the claim: each backend route is live and distinguishable.
    _poll_http(
        backend_base + "/blue", lambda s, h, t: s == 200,
        description=f"GET {backend_base}/blue to become servable",
    )

    # ---- front API: ONE integration whose URI carries the stage variable ----
    front_id = _create_api(ctx, ag, "stage-variable-front")
    which_id = _child(ctx, ag, front_id, "which")
    _retry_throttled(lambda: ag.put_method(
        restApiId=front_id, resourceId=which_id, httpMethod="GET",
        authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=front_id, resourceId=which_id, httpMethod="GET", type="HTTP",
        integrationHttpMethod="GET",
        uri=backend_base + "/${stageVariables.target}",
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=front_id, resourceId=which_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=front_id, resourceId=which_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
    ))

    # ONE deployment, TWO stages off it.
    deployment_id = _retry_throttled(
        lambda: ag.create_deployment(restApiId=front_id))["id"]
    for stage_name in ("blue", "green"):
        _retry_throttled(lambda sn=stage_name: ag.create_stage(
            restApiId=front_id, stageName=sn, deploymentId=deployment_id,
            variables={"target": sn},
            tags={"sim2real": "stage-variable-front"},
        ))
        ctx.on_cleanup(lambda sn=stage_name: _retry_throttled(lambda: ag.delete_stage(
            restApiId=front_id, stageName=sn)))

    blue_dep = ag.get_stage(restApiId=front_id, stageName="blue")["deploymentId"]
    green_dep = ag.get_stage(restApiId=front_id, stageName="green")["deploymentId"]
    assert blue_dep == green_dep == deployment_id, (
        f"both stages must serve the one deployment {deployment_id!r}, got blue="
        f"{blue_dep!r} green={green_dep!r} — the per-stage difference below would "
        f"otherwise be a difference between two deployments"
    )

    blue_url = _apigw_url(ctx, front_id, "blue", "/which")
    green_url = _apigw_url(ctx, front_id, "green", "/which")

    _s, _h, blue_text = _poll_http(
        blue_url, lambda s, h, t: s == 200,
        description=f"GET {blue_url} to be served by the deployed blue stage",
    )
    _s, _h, green_text = _poll_http(
        green_url, lambda s, h, t: s == 200,
        description=f"GET {green_url} to be served by the deployed green stage",
    )
    blue_body = json.loads(blue_text)
    green_body = json.loads(green_text)

    assert blue_body["target"] == markers["blue"], (
        f"the blue stage's ${{stageVariables.target}} must resolve to the blue backend "
        f"({markers['blue']!r}), got {blue_body['target']!r}"
    )
    assert green_body["target"] == markers["green"], (
        f"the green stage's ${{stageVariables.target}} must resolve to the green backend "
        f"({markers['green']!r}), got {green_body['target']!r}"
    )
    assert blue_body["target"] != green_body["target"], (
        f"both stages returned {blue_body['target']!r} from the single deployment "
        f"{deployment_id!r} — the stage variable was not substituted per stage"
    )

    # UpdateStage on the variables map only — no CreateDeployment.
    _retry_throttled(lambda: ag.update_stage(
        restApiId=front_id, stageName="green",
        patchOperations=[{"op": "replace", "path": "/variables/target", "value": "third"}],
    ))
    _s, _h, regreen_text = _poll_http(
        green_url, lambda s, h, t: s == 200 and markers["third"] in t,
        description=(f"GET {green_url} to reach the third backend after UpdateStage "
                     f"re-pointed the variable with no redeploy"),
    )
    assert json.loads(regreen_text)["target"] == markers["third"], (
        f"expected {markers['third']!r} after UpdateStage re-pointed the variable, got "
        f"{json.loads(regreen_text)!r}"
    )
    still_same_deployment = ag.get_stage(
        restApiId=front_id, stageName="green")["deploymentId"]
    assert still_same_deployment == deployment_id, (
        f"the variable update must not have redeployed: stage green is on "
        f"{still_same_deployment!r}, expected the original {deployment_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
