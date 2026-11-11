"""apigw-request-validator-selects-bad-request-body-vs-parameters-gateway-responses."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-request-validator-selects-bad-request-body-vs-parameters-gateway-responses"
GROUP = "methods-integrations"
SERVICES = ["apigateway"]

# Bound for a redeployed stage to start serving the new deployment.
_PROPAGATION_S = 150.0


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage and model names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account."""
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
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _create_api(ctx, ag, scenario):
    """A REGIONAL REST API registered for teardown, marked in name/description/tag."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _http(method, url, body=None, headers=None, timeout=20):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode(errors="replace"))


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=_PROPAGATION_S, interval_s=4.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds; RAISE on the
    deadline rather than returning the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=(status={status}, body={text[:200]!r})"
            )
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A request validator routes a schema-invalid body to BAD_REQUEST_BODY (with a validation
    detail naming the missing property) and a missing required parameter to BAD_REQUEST_PARAMETERS;
    detaching the validator then admits the same refused body.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/supported-gateway-response-types.html
    """
    ag = ctx.client("apigateway")
    prop = f"qty{_unique_token(6)}"           # run-unique, so a canned message cannot contain it
    integration_marker = f"sim2real-{_unique_token()}"
    body_marker = f"sim2real-body-{_unique_token()}"
    params_marker = f"sim2real-params-{_unique_token()}"

    api_id = _create_api(ctx, ag, "request-validator-gateway-responses")
    resource = _child(ctx, ag, api_id, "orders")

    model_name = f"m{_unique_token()}"
    _retry_throttled(lambda: ag.create_model(
        restApiId=api_id, name=model_name, contentType="application/json",
        description=f"sim2real {CHECK}",
        schema=json.dumps({
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {prop: {"type": "integer", "minimum": 1}},
            "required": [prop],
        })))
    validator_id = _retry_throttled(lambda: ag.create_request_validator(
        restApiId=api_id, name=f"v{_unique_token()}",
        validateRequestBody=True, validateRequestParameters=True))["id"]

    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource, httpMethod="POST",
        authorizationType="NONE", requestValidatorId=validator_id,
        requestModels={"application/json": model_name},
        requestParameters={"method.request.querystring.tenant": True}))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource, httpMethod="POST", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource, httpMethod="POST", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource, httpMethod="POST", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json":
                           '{"integration":"%s"}' % integration_marker}))

    # Distinct customisations make the classification observable: the body that comes back says
    # which gateway response produced the 400.
    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="BAD_REQUEST_BODY",
        responseTemplates={"application/json":
                           '{"which":"%s","type":"$context.error.responseType",'
                           '"detail":"$context.error.validationErrorString"}' % body_marker}))
    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="BAD_REQUEST_PARAMETERS",
        responseTemplates={"application/json":
                           '{"which":"%s","type":"$context.error.responseType",'
                           '"detail":"$context.error.validationErrorString"}'
                           % params_marker}))

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    base = _apigw_url(ctx, api_id, stage, "/orders")
    hdrs = {"Content-Type": "application/json"}
    valid_body = json.dumps({prop: 7}).encode()
    body_violating = json.dumps({"unrelated": "x"}).encode()   # omits the required property

    ok_status, _oh, ok_text = _poll_http(
        f"{base}?tenant=acme", lambda s, h, t: s == 200 and integration_marker in t,
        method="POST", body=valid_body, headers=hdrs,
        description=(
            f"POST {base}?tenant=acme with a schema-valid body to be served 200 with marker "
            f"{integration_marker!r}"
        ),
    )
    assert ok_status == 200 and integration_marker in ok_text, (
        f"positive control: a request satisfying both the model and the required query "
        f"parameter must reach the integration; got {ok_status} body {ok_text[:200]!r}"
    )

    b_status, _bh, b_text = _http("POST", f"{base}?tenant=acme", body=body_violating,
                                  headers=hdrs)
    assert b_status == 400, (
        f"expected 400 for a body omitting the model's required property {prop!r} while the "
        f"required query parameter is present, got {b_status} body {b_text[:200]!r}"
    )
    assert integration_marker not in b_text, (
        f"effect-absent: body validation happens before the integration, so the refusal must "
        f"not carry {integration_marker!r}; got {b_text[:200]!r}"
    )
    b_payload = json.loads(b_text)
    assert b_payload.get("which") == body_marker, (
        f"expected the BAD_REQUEST_BODY gateway response (marker {body_marker!r}) to be "
        f"served, got {b_payload!r} — the params marker means the wrong branch fired, and "
        f"neither marker means it fell through to DEFAULT_4XX"
    )
    assert b_payload.get("type") == "BAD_REQUEST_BODY", (
        f"expected $context.error.responseType to substitute to 'BAD_REQUEST_BODY', got "
        f"{b_payload.get('type')!r} (full body {b_payload!r})"
    )
    # validationErrorString has no documented format, so only the property name is asserted.
    assert prop in str(b_payload.get("detail", "")), (
        f"expected $context.error.validationErrorString to name the run-unique required "
        f"property {prop!r} that this run's model declared — a canned or recorded validation "
        f"message cannot contain it; got detail={b_payload.get('detail')!r}"
    )

    p_status, _ph, p_text = _http("POST", base, body=valid_body, headers=hdrs)
    assert p_status == 400, (
        f"expected 400 for a schema-valid body with the required query parameter 'tenant' "
        f"omitted, got {p_status} body {p_text[:200]!r}"
    )
    assert integration_marker not in p_text, (
        f"effect-absent: parameter validation happens before the integration, so the refusal "
        f"must not carry {integration_marker!r}; got {p_text[:200]!r}"
    )
    p_payload = json.loads(p_text)
    assert p_payload.get("which") == params_marker, (
        f"expected the BAD_REQUEST_PARAMETERS gateway response (marker {params_marker!r}) "
        f"to be served for a missing required parameter, got {p_payload!r} — serving the "
        f"BAD_REQUEST_BODY marker {body_marker!r} here means the two validation failures "
        f"were not classified apart"
    )
    assert p_payload.get("type") == "BAD_REQUEST_PARAMETERS", (
        f"expected $context.error.responseType to substitute to 'BAD_REQUEST_PARAMETERS', "
        f"got {p_payload.get('type')!r} (full body {p_payload!r})"
    )
    assert prop not in str(p_payload.get("detail", "")), (
        f"a parameter failure must not report the body model's property {prop!r} as the "
        f"validation detail; got detail={p_payload.get('detail')!r}"
    )

    # Detaching the validator admits the same body, attributing the 400 to the validator.
    _retry_throttled(lambda: ag.update_method(
        restApiId=api_id, resourceId=resource, httpMethod="POST",
        patchOperations=[{"op": "replace", "path": "/requestValidatorId", "value": ""}]))
    detached = ag.get_method(restApiId=api_id, resourceId=resource, httpMethod="POST")
    assert not detached.get("requestValidatorId"), (
        f"expected GetMethod to report no requestValidatorId after detaching it, got "
        f"{detached.get('requestValidatorId')!r}"
    )
    redeployed = _retry_throttled(
        lambda: ag.create_deployment(restApiId=api_id, stageName=stage))["id"]
    assert redeployed != deployment, (
        f"expected a NEW deployment id for the restore redeploy, got {redeployed!r}"
    )
    r_status, _rh, r_text = _poll_http(
        f"{base}?tenant=acme", lambda s, h, t: s == 200 and integration_marker in t,
        method="POST", body=body_violating, headers=hdrs,
        description=(
            f"POST {base}?tenant=acme with the IDENTICAL previously-refused body to reach "
            f"the integration once the validator is detached and the API redeployed"
        ),
    )
    assert r_status == 200 and integration_marker in r_text, (
        f"restore: with the validator detached the identical body that was refused with 400 "
        f"must reach the integration — this is what attributes the refusal to the validator; "
        f"got {r_status} body {r_text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
