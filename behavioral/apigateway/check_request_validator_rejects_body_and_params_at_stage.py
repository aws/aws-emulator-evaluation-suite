"""request-validator-rejects-body-and-params-at-stage."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "request-validator-rejects-body-and-params-at-stage"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']

_JSON = {"Content-Type": "application/json"}


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
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
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

def _message(text):
    """The `message` field of an execute-api error body."""
    try:
        return json.loads(text).get("message")
    except (ValueError, AttributeError):
        return None


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """At a deployed stage a RequestValidator rejects a schema-violating body and a missing required
    query parameter with their exact messages before the MOCK integration runs, and a valid
    request on the same route afterwards is served normally."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "widgets")

    model_name = "Sim2realBehav" + _unique_token()
    ag.create_model(
        restApiId=api_id, name=model_name, contentType="application/json",
        schema=json.dumps({
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }),
    )
    validator_id = ag.create_request_validator(
        restApiId=api_id, name=ctx.unique_name("sim2real-behav-rv-"),
        validateRequestBody=True, validateRequestParameters=True,
    )["id"]

    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST",
        authorizationType="NONE", requestValidatorId=validator_id,
        requestModels={"application/json": model_name},
        requestParameters={"method.request.querystring.tenant": True},
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
        selectionPattern="",
        responseTemplates={
            "application/json": '{"integration":"ran","tenant":"$input.params(\'tenant\')"}'
        },
    )

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    valid_url = _apigw_url(ctx, api_id, stage, "/widgets") + "?tenant=acme"
    valid_body = json.dumps({"name": "widget-1"}).encode()
    _, _, text = _poll_http(
        valid_url, lambda s, h, t: s == 200, method="POST", body=valid_body,
        headers=_JSON,
        description=f"POST {valid_url} with a schema-valid body to serve 200",
    )
    assert json.loads(text) == {"integration": "ran", "tenant": "acme"}, (
        f"precondition: a valid request must reach the MOCK integration and echo the "
        f"query parameter, got {text!r}"
    )

    # Break exactly one thing: the required query parameter is absent.
    no_param_url = _apigw_url(ctx, api_id, stage, "/widgets")
    status, _, text = _http("POST", no_param_url, body=valid_body, headers=_JSON)
    assert status == 400, (
        f"expected 400 when the validator's required querystring parameter is "
        f"missing, got {status}: {text!r}"
    )
    assert _message(text) == "Missing required request parameters: [tenant]", (
        f'expected {{"message":"Missing required request parameters: [tenant]"}}, '
        f"got {text!r}"
    )
    assert "integration" not in (text or ""), (
        f"the integration must not run for a parameter-validation failure, but the "
        f"response carries integration output: {text!r}"
    )

    # Break exactly one thing: the body omits the model's required property.
    bad_body = json.dumps({"unexpected-field-not-name": "value"}).encode()
    status, _, text = _http("POST", valid_url, body=bad_body, headers=_JSON)
    assert status == 400, (
        f"expected 400 when the body violates the attached JSON-schema model, "
        f"got {status}: {text!r}"
    )
    assert _message(text) == "Invalid request body", (
        f'expected {{"message":"Invalid request body"}}, got {text!r}'
    )
    assert "integration" not in (text or ""), (
        f"the integration must not run for a body-validation failure, but the "
        f"response carries integration output: {text!r}"
    )

    # Control: the rejections are input-scoped; the route still serves valid input.
    status, _, text = _http("POST", valid_url, body=valid_body, headers=_JSON)
    assert status == 200 and json.loads(text).get("integration") == "ran", (
        f"control: a valid request must still reach the integration after the "
        f"rejections, got {status}: {text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
