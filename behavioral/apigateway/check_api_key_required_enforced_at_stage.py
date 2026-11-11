"""api-key-required-enforced-at-stage."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "api-key-required-enforced-at-stage"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']

_FORBIDDEN = "Forbidden"


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

def _delete_usage_plan(ag, plan_id, api_id, stage):
    """A usage plan with associated API stages cannot be deleted; detach then delete."""
    try:
        ag.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages",
                              "value": f"{api_id}:{stage}"}],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    ag.delete_usage_plan(usagePlanId=plan_id)

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

    A REST API deployment (and an api-key/usage-plan association) becomes effective on
    a stage asynchronously, so each first touch polls to a condition with a bounded
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A method with apiKeyRequired serves only a request whose x-api-key is an enabled key in a usage plan
    covering the stage: no key, a key outside the plan, an unknown key and a disabled key each get the
    same opaque 403 {"message":"Forbidden"}, while an associated enabled key is served."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "guarded")

    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE", apiKeyRequired=True,
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"marker":"key-accepted"}'},
    )
    assert ag.get_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET"
    )["apiKeyRequired"] is True, "precondition: apiKeyRequired must round-trip as True"

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    plan_id = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage}],
        throttle={"rateLimit": 20.0, "burstLimit": 10},
        quota={"limit": 1000, "period": "DAY"},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(ag, plan_id, api_id, stage))

    associated = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"), enabled=True,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=associated["id"]))
    unassociated = ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-other-"), enabled=True,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=unassociated["id"]))
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=associated["id"], keyType="API_KEY")
    ctx.on_cleanup(
        lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=associated["id"])
    )

    url = _apigw_url(ctx, api_id, stage, "/guarded")
    # A single request that reads 200 does not mean the NEXT request also does: the
    # key/usage-plan association propagates across regional edge nodes independently, so
    # a fresh follow-up call can still land on a stale node. Poll for status AND the
    # mock integration's body together so the assertion below is checked against the
    # exact response that satisfied the predicate, not a second, separately-routed call.
    status, _, text = _poll_http(
        url, lambda s, h, t: s == 200 and "key-accepted" in t,
        headers={"x-api-key": associated["value"]},
        description=(
            f"GET {url} with the enabled, plan-associated api key to serve 200 with the "
            f"MOCK integration's body (key/usage-plan association propagation)"
        ),
    )
    assert json.loads(text).get("marker") == "key-accepted", (
        f"precondition: the authorized request must reach the MOCK integration, "
        f"got {status}: {text!r}"
    )

    rejections = [
        (None, "no x-api-key header at all"),
        (unassociated["value"], "a real, enabled api key that is NOT in the usage plan"),
        ("Sim2RealNotARealApiKeyValue0000000000000", "an unknown api key value"),
    ]
    for key_value, why in rejections:
        headers = {} if key_value is None else {"x-api-key": key_value}
        status, _, text = _http("GET", url, headers=headers)
        assert status == 403, (
            f"expected 403 for {why} on a method with apiKeyRequired=True, got "
            f"{status}: {text!r}"
        )
        assert _message(text) == _FORBIDDEN, (
            f'expected the opaque body {{"message":"{_FORBIDDEN}"}} for {why} '
            f"(the response must not disclose which condition failed), got {text!r}"
        )
        assert "key-accepted" not in (text or ""), (
            f"the integration must not run for {why}, got {text!r}"
        )

    # Disabling the associated key must revoke access without touching any wiring.
    ag.update_api_key(
        apiKey=associated["id"],
        patchOperations=[{"op": "replace", "path": "/enabled", "value": "false"}],
    )
    assert ag.get_api_key(apiKey=associated["id"])["enabled"] is False, (
        "expected UpdateApiKey replace /enabled=false to round-trip"
    )
    _poll_http(
        url, lambda s, h, t: s == 403 and _message(t) == _FORBIDDEN,
        headers={"x-api-key": associated["value"]},
        description=(
            f"GET {url} with the now-DISABLED api key to be refused 403 Forbidden"
        ),
    )

    # Control: re-enabling the same key restores access, proving the refusal tracked
    # key state rather than permanently poisoning the route.
    ag.update_api_key(
        apiKey=associated["id"],
        patchOperations=[{"op": "replace", "path": "/enabled", "value": "true"}],
    )
    _poll_http(
        url, lambda s, h, t: s == 200 and "key-accepted" in t,
        headers={"x-api-key": associated["value"]},
        description=f"GET {url} to serve 200 again once the api key is re-enabled",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
