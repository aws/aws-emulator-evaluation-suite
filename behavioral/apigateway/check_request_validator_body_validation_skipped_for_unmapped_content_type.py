"""request-validator-body-validation-skipped-for-unmapped-content-type."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-validator-body-validation-skipped-for-unmapped-content-type"
GROUP = "methods-integrations"
SERVICES = ["apigateway"]

_PROPAGATION_S = 150.0
_THROTTLED = ("TooManyRequestsException", "Too Many Requests")


def _error_pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _stage_name(ctx) -> str:
    """A unique stage name: apigateway stage names reject hyphens."""
    return "s" + ctx.unique_name("")


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only the control plane's throttle with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so
    other activity in the same account can surface as a throttle unrelated to the claim."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _error_pair(exc) != _THROTTLED or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _http(method, url, body=None, headers=None, timeout=20):
    """HTTP request; returns (status, body text), or (None, "") on a connection-level failure —
    a retryable "not yet" signal for the poll, distinct from a definite HTTP status."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except urllib.error.URLError:
        return None, ""


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=_PROPAGATION_S, interval_s=4.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, text) holds; RAISE on the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, text = _http(method, url, body=body, headers=headers)
        if predicate(status, text):
            return status, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=(status={status}, body={text[:200]!r})"
            )
        time.sleep(interval_s)


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _delete_rest_api_quota_aware(ag, api_id: str, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd to one call every 30s per account, so two APIs in one check's
    cleanup chain must serialize through it; retry the throttle across that window."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            if _error_pair(exc) != _THROTTLED or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _invoke_policy(ctx) -> str:
    """A resource policy admitting execute-api:Invoke only from the runner's own egress."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": "execute-api:/*",
            "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}},
        }],
    })


def _create_api(ctx, ag, scenario, policy=None):
    extra = {"policy": policy} if policy is not None else {}
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
        **extra,
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(ag, api_id))
    return api_id


def _backend_echo(ctx, ag):
    """A deployed stage whose POST /echo MOCK integration always answers 200, regardless of
    the request body or Content-Type it is called with. Only API Gateway's own HTTP integration
    calls it, from AWS's addresses, so it carries no source-address policy; it serves a constant
    body and no data."""
    backend_id = _create_api(ctx, ag, "request-validator-unmapped-content-type-backend")
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=backend_id, parentId=_root_id(ag, backend_id), pathPart="echo"))["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=backend_id, resourceId=resource_id, httpMethod="POST", authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=backend_id, resourceId=resource_id, httpMethod="POST", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=backend_id, resourceId=resource_id, httpMethod="POST", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=backend_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"message": "accepted"}'}))
    stage = _stage_name(ctx)
    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=backend_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=backend_id, stageName=stage, deploymentId=deployment_id, tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=backend_id, stageName=stage)))
    return f"{ctx.rest_api_url(backend_id, stage)}/echo"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A requestModels entry configured only for application/json skips body validation for a
    request whose Content-Type matches no model, letting a schema-violating body reach the
    integration, while the identical body under application/json is rejected 400."""
    ag = ctx.client("apigateway")

    backend_url = _backend_echo(ctx, ag)

    api_id = _create_api(ctx, ag, "request-validator-unmapped-content-type", _invoke_policy(ctx))
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart="items"))["id"]

    model_name = "ItemInput"
    schema = json.dumps({
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": model_name,
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    })
    _retry_throttled(lambda: ag.create_model(
        restApiId=api_id, name=model_name, contentType="application/json", schema=schema))

    validator_id = _retry_throttled(lambda: ag.create_request_validator(
        restApiId=api_id, name=ctx.unique_name("sim2real-behav-validator-"),
        validateRequestBody=True, validateRequestParameters=False))["id"]

    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", authorizationType="NONE",
        requestValidatorId=validator_id,
        # The model is configured ONLY for application/json; text/plain has no entry.
        requestModels={"application/json": model_name}))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", type="HTTP",
        integrationHttpMethod="POST", uri=backend_url,
        passthroughBehavior="WHEN_NO_MATCH",
        requestTemplates={"application/json": "$input.body"},
        # The backend always sees application/json: passthroughBehavior alone decides whether
        # an unmapped-content-type request reaches it at all, independent of validation.
        requestParameters={"integration.request.header.Content-Type": "'application/json'"}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200", selectionPattern=""))

    stage = _stage_name(ctx)
    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id, tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    url = f"{ctx.rest_api_url(api_id, stage)}/items"
    # Reused verbatim across all three invocations below: it violates the model's schema
    # (missing the required "name" property), and only the Content-Type header differs.
    invalid_body = json.dumps({"unexpected": "field"}).encode()

    # ---- beat 1: positive control — the invalid body under a Content-Type with NO configured
    # model reaches the integration, because body validation is not performed for it. ----
    unmapped_status, unmapped_text = _poll_http(
        url, lambda s, t: s in (200, 400), method="POST", body=invalid_body,
        headers={"Content-Type": "text/plain"},
        description=f"POST {url} with an unmapped text/plain Content-Type to reach a terminal response",
    )
    assert unmapped_status == 200, (
        f"expected 200 for a schema-invalid body under text/plain (no model configured for "
        f"it), got {unmapped_status} with body {unmapped_text[:200]!r}"
    )
    assert unmapped_text == '{"message": "accepted"}', (
        f"expected the body to reach the integration, got {unmapped_text!r}"
    )

    # ---- beat 2: the identical body under application/json, which DOES have a configured
    # model, is rejected before the integration runs. ----
    mapped_status, mapped_text = _poll_http(
        url, lambda s, t: s in (200, 400), method="POST", body=invalid_body,
        headers={"Content-Type": "application/json"}, timeout_s=30.0,
        description=f"POST {url} with application/json to reach a terminal response",
    )
    assert mapped_status == 400, (
        f"expected 400 for the same body under application/json (model configured), got "
        f"{mapped_status} with body {mapped_text[:200]!r}"
    )
    assert mapped_text == '{"message": "Invalid request body"}', (
        f"expected the validator's exact rejection body, got {mapped_text!r}"
    )

    # ---- beat 3: a schema-valid body under application/json still passes, so beat 2's 400
    # is the validator rejecting THIS body, not every request on this content type. ----
    valid_status, valid_text = _poll_http(
        url, lambda s, t: s in (200, 400), method="POST",
        body=json.dumps({"name": "widget"}).encode(), headers={"Content-Type": "application/json"},
        timeout_s=30.0,
        description=f"POST {url} with a schema-valid application/json body to reach a terminal response",
    )
    assert valid_status == 200, (
        f"expected 200 for a schema-valid body under application/json, got "
        f"{valid_status} with body {valid_text[:200]!r}"
    )
    assert valid_text == '{"message": "accepted"}', valid_text


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
