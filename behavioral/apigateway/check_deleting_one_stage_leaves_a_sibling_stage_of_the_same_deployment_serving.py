"""deleting-one-stage-leaves-a-sibling-stage-of-the-same-deployment-serving."""
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

CHECK = "deleting-one-stage-leaves-a-sibling-stage-of-the-same-deployment-serving"
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

def _throttle_retry(fn, *, attempts=4, base_delay=5.0, max_delay=15.0):
    """Call fn(), retrying only TooManyRequestsException (DeleteRestApi is rate limited per
    account) for at most about 35 s; the last error, or any other one, propagates."""
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
    """Invoke URL for a deployed stage, from ctx.rest_api_url."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(url, predicate, verify, *, method="GET", body=None, headers=None,
               timeout_s=40.0, interval_s=3.0, description="stage response"):
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


def _body(text):
    """The response body parsed as JSON, or the raw text when it is not JSON."""
    try:
        return json.loads(text)
    except ValueError:
        return text


# ===== end helpers =====

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two stages on one deployment each serve the MOCK body with their own $context.stage and stage
    variable; deleting one stops only that stage while its sibling keeps serving and the deployment
    survives, and deleting the API stops the sibling too."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "status")
    template = '{"stage":"$context.stage","color":"$stageVariables.color","method":"$context.httpMethod"}'
    _mock_method(ag, api_id, resource_id, "GET", template)
    color_kept, color_doomed = f"k{_unique_token(8)}", f"d{_unique_token(8)}"
    deployment_id, kept = _deploy(ctx, ag, api_id, variables={"color": color_kept})
    doomed = f"s{_unique_token()}"
    ag.create_stage(restApiId=api_id, stageName=doomed, deploymentId=deployment_id,
                    variables={"color": color_doomed}, tags={"sim2real": CHECK})
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_stage(restApiId=api_id, stageName=doomed)))

    kept_url = _apigw_url(ctx, api_id, kept, "/status")
    doomed_url = _apigw_url(ctx, api_id, doomed, "/status")
    kept_body = {"stage": kept, "color": color_kept, "method": "GET"}
    doomed_body = {"stage": doomed, "color": color_doomed, "method": "GET"}
    for url, want in ((kept_url, kept_body), (doomed_url, doomed_body)):
        _, _, text = _poll_http(url, lambda s, h, t: s == 200, ctx.http_verify,
                                description=f"GET {url} to serve the deployed MOCK integration")
        assert json.loads(text) == want, f"GET {url}: expected {want!r}, got {text!r}"

    ag.delete_stage(restApiId=api_id, stageName=doomed)
    _not_found(lambda: ag.get_stage(restApiId=api_id, stageName=doomed), "GetStage on the deleted stage",
               "Invalid stage identifier specified")
    kept_stage = ag.get_stage(restApiId=api_id, stageName=kept)
    assert (kept_stage["deploymentId"], kept_stage.get("variables")) == (deployment_id, {"color": color_kept}), (
        f"the sibling stage changed when its neighbour was deleted: {kept_stage!r}"
    )
    stage_names = sorted(i["stageName"] for i in ag.get_stages(restApiId=api_id).get("item", []))
    assert stage_names == [kept], f"GetStages: expected only {[kept]!r}, got {stage_names!r}"
    deployment = ag.get_deployment(restApiId=api_id, deploymentId=deployment_id)
    assert deployment["id"] == deployment_id, f"GetDeployment returned {deployment!r}"

    # Stage removal propagates asynchronously; once the URL stops serving it answers Forbidden.
    gone = _poll_http(doomed_url, lambda s, h, t: s != 200 and color_doomed not in t, ctx.http_verify,
                      description=f"GET {doomed_url} to stop serving after DeleteStage")
    assert (gone[0], _body(gone[2])) == (403, {"message": "Forbidden"}), (
        f"GET on the deleted stage: expected (403, {{'message': 'Forbidden'}}), got ({gone[0]}, {gone[2]!r})"
    )
    # Twin control: the sibling stage of the same deployment still serves, after the deleted one stopped.
    status, _, text = _http("GET", kept_url, ctx.http_verify)
    assert (status, json.loads(text)) == (200, kept_body), (
        f"sibling stage after the delete: expected (200, {kept_body!r}), got ({status}, {text!r})"
    )

    _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id))
    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _not_found(lambda: ag.get_rest_api(restApiId=api_id), "GetRestApi on the deleted API", api_gone)
    _not_found(lambda: ag.get_stage(restApiId=api_id, stageName=kept), "GetStage on the deleted API",
               "Invalid stage identifier specified")
    gone = _poll_http(
        kept_url, lambda s, h, t: s != 200 and color_kept not in t, ctx.http_verify,
        description=f"GET {kept_url} to stop serving after DeleteRestApi",
    )
    assert (gone[0], _body(gone[2])) == (403, {"message": "Forbidden"}), (
        f"GET on the deleted API's stage: expected (403, {{'message': 'Forbidden'}}), got ({gone[0]}, {gone[2]!r})"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
