"""stage-serves-deployed-snapshot-not-live-config."""
from __future__ import annotations

import json
import random
import ssl
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-serves-deployed-snapshot-not-live-config"
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
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    return api_id

def _delete_rest_api(ag, api_id, *, attempts=10, delay_s=15.0):
    """Teardown: DeleteRestApi through its ~1 req/30 s account throttle; NotFound is tolerated,
    any other error (or a throttle that never clears) raises."""
    for i in range(attempts):
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or i == attempts - 1:
                raise
            time.sleep(min(delay_s * 2 ** i, 35.0))

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

def _tls(ctx):
    """The TLS context ctx.http_verify asks for: a CA bundle path, unverified, or the default."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)

def _http(ctx, method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=_tls(ctx)) as resp:  # noqa: S310 - fixed http(s) scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())

def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(ctx, url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=120.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A REST API deployment becomes servable on its stage asynchronously, so the first
    touch of a freshly (re-)deployed stage polls to a condition with a bounded
    deadline rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(ctx, method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=({status}, {text!r})"
            )
        time.sleep(interval_s)

def _not_found(fn, what):
    """fn() must raise NotFoundException with HTTP 404 and the exact message."""
    try:
        result = fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message") or ""
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert code == "NotFoundException", f"{what}: expected NotFoundException, got {code!r}"
        assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
        expected_message = "Invalid Deployment identifier specified"
        assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
        return
    raise AssertionError(f"{what}: expected NotFoundException, but the call SUCCEEDED: {result!r}")

def _snapshot(text):
    """The 'snapshot' field of a served JSON body (None if unparseable)."""
    try:
        return json.loads(text).get("snapshot")
    except (ValueError, AttributeError):
        return None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stage serves its deployed snapshot: an edited integration response is not served until a
    new deployment is created and UpdateStage repoints /deploymentId at it, after which it is.
    The unreferenced old deployment is then deletable."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "snapshot")
    _mock_method(ag, api_id, resource_id, "GET", '{"snapshot":"v1"}')

    deployment_v1 = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_v1,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    url = _apigw_url(ctx, api_id, stage, "/snapshot")
    try:
        _poll_http(
            ctx, url, lambda s, h, t: s == 200 and _snapshot(t) == "v1",
            description=f"GET {url} to serve deployment snapshot v1",
        )
    except (urllib.error.URLError, OSError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the deployed stage's execute-api URL {url} could not be "
            f"reached, so no request was served: {type(exc).__name__}: {exc}"
        ) from exc

    # Edit the LIVE integration response. No deployment is created.
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"snapshot":"v2"}'},
    )
    live = ag.get_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    assert live["responseTemplates"]["application/json"] == '{"snapshot":"v2"}', (
        f"precondition: the LIVE integration response should now be v2, got "
        f"{live.get('responseTemplates')!r}"
    )

    # Freeze detector: after the live edit was read back, 3 consecutive samples must still
    # answer the deployed snapshot v1 (no fixed sleep is the barrier).
    for attempt in range(3):
        status, _, text = _http(ctx, "GET", url)
        assert status == 200 and _snapshot(text) == "v1", (
            f"an undeployed config edit leaked onto stage {stage!r} on sample "
            f"{attempt + 1}: expected the deployed snapshot v1, got "
            f"({status}, {text!r}). The stage must serve deployment "
            f"{deployment_v1!r} until its deploymentId changes."
        )

    # Now snapshot the edit into a new deployment and repoint the stage at it.
    deployment_v2 = ag.create_deployment(restApiId=api_id)["id"]
    assert deployment_v2 != deployment_v1, (
        f"expected a distinct new deployment id, got {deployment_v2!r} twice"
    )
    status, _, text = _http(ctx, "GET", url)
    assert status == 200 and _snapshot(text) == "v1", (
        f"creating a deployment must not move a stage that was never repointed: "
        f"expected v1 on stage {stage!r}, got ({status}, {text!r})"
    )

    ag.update_stage(
        restApiId=api_id, stageName=stage,
        patchOperations=[{"op": "replace", "path": "/deploymentId",
                          "value": deployment_v2}],
    )
    assert ag.get_stage(restApiId=api_id, stageName=stage)["deploymentId"] == deployment_v2, (
        "expected UpdateStage patchOperations replace /deploymentId to repoint the stage"
    )
    _poll_http(
        ctx, url, lambda s, h, t: s == 200 and _snapshot(t) == "v2",
        description=f"GET {url} to serve deployment snapshot v2 after repointing the stage",
    )

    # The now-unreferenced v1 deployment is deletable, and then gone.
    ag.delete_deployment(restApiId=api_id, deploymentId=deployment_v1)
    _not_found(
        lambda: ag.get_deployment(restApiId=api_id, deploymentId=deployment_v1),
        "GetDeployment on the deleted deployment",
    )
    listed = [
        d.get("id")
        for page in ag.get_paginator("get_deployments").paginate(restApiId=api_id)
        for d in page.get("items", [])
    ]
    assert deployment_v1 not in listed, f"deleted deployment still listed by GetDeployments: {listed!r}"
    _not_found(
        lambda: ag.update_deployment(
            restApiId=api_id, deploymentId=deployment_v1,
            patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
        ),
        "UpdateDeployment on the deleted deployment",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
