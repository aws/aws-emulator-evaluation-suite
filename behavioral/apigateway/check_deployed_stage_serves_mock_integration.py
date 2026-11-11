"""deployed-stage-serves-mock-integration."""
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

CHECK = "deployed-stage-serves-mock-integration"
GROUP = 'invoke'
SERVICES = ['apigateway']


# ===== helpers (self-contained) =====
def _tolerate_gone(fn):
    """Teardown that tolerates NotFoundException: the check deletes these itself on success."""
    def run_it():
        try:
            _throttle_retry(fn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    return run_it

def _throttle_retry(fn, *, attempts=10, base_delay=15.0, max_delay=35.0):
    """Call fn(), retrying only TooManyRequestsException (DeleteRestApi is capped near 1 req/30s
    per account); any other error propagates."""
    delay = base_delay
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or i == attempts - 1:
                raise
            time.sleep(min(delay, max_delay))
            delay *= 2

def _not_found(fn, what, message):
    """fn() must raise NotFoundException with HTTP 404 and exactly ``message``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert got == ("NotFoundException", message), (
            f"{what}: expected ('NotFoundException', {message!r}), got {got!r}"
        )
        assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
        return
    raise AssertionError(f"{what}: expected NotFoundException, but the call SUCCEEDED: {result!r}")

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
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    A REST API's only handle is a server-minted id, so
    the tag carries the sim2real marker too."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id

def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    )["id"]
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id

def _mock_method(ag, api_id, resource_id, http_method, response_template,
                 request_parameters=None):
    """A fully wired MOCK method: 200 request template + 200 integration response."""
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE", requestParameters=request_parameters or {},
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

def _deploy(ctx, ag, api_id, variables=None):
    """CreateDeployment + CreateStage; returns (deployment_id, stage_name)."""
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage_name = f"s{_unique_token()}"
    kwargs = {
        "restApiId": api_id, "stageName": stage_name, "deploymentId": deployment_id,
        "tags": {"sim2real": CHECK},
    }
    if variables:
        kwargs["variables"] = variables
    ag.create_stage(**kwargs)
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_stage(restApiId=api_id, stageName=stage_name)))
    return deployment_id, stage_name

def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)

def _http(method, url, verify, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify)) as resp:  # noqa: S310 - fixed http(s) scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())
    except (urllib.error.URLError, OSError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the deployed stage at {url} did not answer: {exc!r}"
        ) from exc

def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(url, predicate, verify, *, method="GET", body=None, headers=None,
               timeout_s=120.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A REST API deployment becomes servable on its stage asynchronously, so the first
    touch of a freshly (re-)deployed stage polls to a condition with a bounded
    deadline rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status, resp_headers, text = _http(method, url, verify, body=body, headers=headers)
        except AssertionError:
            # A connection error while the stage propagates is retried; the last one is raised
            # as DATAPLANE_UNIMPLEMENTED once the deadline passes.
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            continue
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=({status}, {text!r})"
            )
        time.sleep(interval_s)


# ===== end helpers =====

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed stage serves the MOCK integration over its execute-api URL with $context taken
    from the real request and serving stage; deleting the stage stops it serving and makes it
    unreadable, unlisted and unmutable, and the same holds for the API once deleted."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "ping")
    template = (
        '{"marker":"served-by-deployed-stage",'
        '"stage":"$context.stage",'
        '"httpMethod":"$context.httpMethod",'
        '"resourcePath":"$context.resourcePath"}'
    )
    _mock_method(ag, api_id, resource_id, "GET", template)
    _, stage = _deploy(ctx, ag, api_id)

    url = _apigw_url(ctx, api_id, stage, "/ping")
    status, headers, text = _poll_http(
        url, lambda s, h, t: s == 200, ctx.http_verify,
        description=f"GET {url} to serve the deployed MOCK integration",
    )
    assert status == 200, f"expected 200 from the deployed stage, got {status}: {text}"
    assert headers.get("content-type", "").startswith("application/json"), (
        f"expected an application/json content-type for the mapped MOCK response, "
        f"got {headers.get('content-type')!r}"
    )
    data = json.loads(text)
    assert data.get("marker") == "served-by-deployed-stage", (
        f"expected the integration response template to be applied to the real "
        f"request, got {data!r}"
    )
    assert data.get("stage") == stage, (
        f"expected $context.stage to be the stage that served the request "
        f"({stage!r}), got {data.get('stage')!r}"
    )
    assert data.get("httpMethod") == "GET", (
        f"expected $context.httpMethod to reflect the real request method, got {data!r}"
    )
    assert data.get("resourcePath") == "/ping", (
        f"expected $context.resourcePath to be the matched resource path '/ping', "
        f"got {data.get('resourcePath')!r}"
    )

    # The stage is a durable artifact, not a one-shot: a second request answers
    # identically (no first-request-only warm path, no per-request drift).
    status2, _, text2 = _http("GET", url, ctx.http_verify)
    assert status2 == 200 and json.loads(text2) == data, (
        f"expected the deployed stage to answer a repeat request identically, "
        f"got ({status2}, {text2!r}) after ({status}, {text!r})"
    )

    ag.delete_stage(restApiId=api_id, stageName=stage)
    # Beat 1: the stage read is NotFoundException 404.
    _not_found(lambda: ag.get_stage(restApiId=api_id, stageName=stage), "GetStage on the deleted stage",
               "Invalid stage identifier specified")
    # Beat 2: the stage is absent from the API's stage listing.
    stage_names = [i.get("stageName") for i in ag.get_stages(restApiId=api_id).get("item", [])]
    assert stage not in stage_names, f"deleted stage still listed by GetStages: {stage_names!r}"
    # Beat 3: a mutation on the dead stage is refused.
    _not_found(
        lambda: ag.update_stage(
            restApiId=api_id, stageName=stage,
            patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
        ),
        "UpdateStage on the deleted stage", "Invalid stage identifier specified",
    )
    # The invoke URL stops serving the marker (stage removal propagates asynchronously).
    gone_status, _, gone_text = _poll_http(
        url, lambda s, h, t: s != 200 and "served-by-deployed-stage" not in t, ctx.http_verify,
        description=f"GET {url} to stop serving after DeleteStage",
    )
    assert gone_status != 200, f"expected the deleted stage to stop serving, got {gone_status}"

    _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id))
    # Beat 1: the API read is NotFoundException 404.
    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _not_found(lambda: ag.get_rest_api(restApiId=api_id), "GetRestApi on the deleted API", api_gone)
    # Beat 2: the API is absent from the paginated GetRestApis listing.
    api_ids = [
        i["id"] for page in ag.get_paginator("get_rest_apis").paginate() for i in page.get("items", [])
    ]
    assert api_id not in api_ids, f"deleted REST API {api_id} still listed by GetRestApis"
    # Beat 3: a mutation on the dead API is refused.
    _not_found(
        lambda: ag.update_rest_api(
            restApiId=api_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
        ),
        "UpdateRestApi on the deleted API", api_gone,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
