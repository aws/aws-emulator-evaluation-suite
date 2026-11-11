"""apigw-request-parameter-required-rejection-happens-before-the-integration."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-request-parameter-required-rejection-happens-before-the-integration"
GROUP = 'overly-permissive'
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
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https
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
    """Re-issue an HTTP request until predicate(status, headers, text) holds, bounded."""
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A method with a REQUIRED query parameter behind a validateRequestParameters validator
    answers 400 "Missing required request parameters: [who]" without running the integration
    (its marker is absent), repeatedly, while the same request with the parameter reaches it."""
    ag = ctx.client("apigateway")
    marker = f"sim2real-{_unique_token()}"

    api_id = _create_api(ctx, ag, "required-request-parameter")
    validator_id = _retry_throttled(lambda: ag.create_request_validator(
        restApiId=api_id, name=ctx.unique_name("sim2real-behav-validator-"),
        validateRequestParameters=True, validateRequestBody=False,
    ))["id"]
    needs_id = _child(ctx, ag, api_id, "needs")
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=needs_id, httpMethod="GET",
        authorizationType="NONE", requestValidatorId=validator_id,
        requestParameters={"method.request.querystring.who": True},
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=needs_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=needs_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=needs_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": (
            '{"who":"$input.params(\'who\')","integration_marker":"%s"}' % marker
        )},
    ))
    stored = ag.get_method(restApiId=api_id, resourceId=needs_id, httpMethod="GET")
    assert stored.get("requestValidatorId") == validator_id, (
        f"precondition: the method must be wired to the validator before the data plane "
        f"can be graded, got {stored.get('requestValidatorId')!r}"
    )

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="test", deploymentId=deployment_id,
        tags={"sim2real": "required-request-parameter"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="test")))

    url = _apigw_url(ctx, api_id, "test", "/needs")

    bad_status, _bh, bad_body = _poll_http(
        url, lambda s, h, t: s == 400,
        description=(f"GET {url} with no query string to be rejected by the deployed "
                     f"stage's request validator"),
    )
    assert bad_status == 400, (
        f"expected 400 for a missing required request parameter, got {bad_status!r} "
        f"body={bad_body!r}"
    )
    assert json.loads(bad_body)["message"] == "Missing required request parameters: [who]", (
        f"unexpected validation message: {bad_body!r}"
    )
    assert marker not in bad_body, (
        f"the integration's response template ran on a request the validator was supposed "
        f"to short-circuit: {marker!r} appears in {bad_body!r}"
    )

    repeat_statuses = [_http("GET", url)[0] for _ in range(5)]
    assert set(repeat_statuses) == {400}, (
        f"the validator must reject every parameterless request, not just the first; got "
        f"{repeat_statuses!r}"
    )

    good_status, _gh, good_body = _http("GET", f"{url}?who={marker}")
    assert good_status == 200, (
        f"control: the request carrying ?who= must reach the integration, got "
        f"{good_status!r}: {good_body!r}"
    )
    good = json.loads(good_body)
    assert good == {"who": marker, "integration_marker": marker}, (
        f"control: expected the integration's own response template with {marker!r} in "
        f"both fields, got {good!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
