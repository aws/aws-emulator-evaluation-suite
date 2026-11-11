"""resource-policy-denies-unlisted-path-at-stage."""
from __future__ import annotations

import json
import random
import re
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "resource-policy-denies-unlisted-path-at-stage"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']

_NOT_AUTHORIZED = "not authorized to perform: execute-api:Invoke"


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
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the
    emulator's /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=120.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A REST API deployment (and a resource-policy change, which takes effect on the next
    deployment) becomes servable asynchronously, so each first touch polls to a
    condition with a bounded deadline rather than sleeping a fixed amount."""
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
    """The message field of an execute-api error body, under either casing.

    The gateway's own 403s use a lowercase `message`, while a resource-policy denial uses a
    capitalised `Message`; which key a given 403 uses is asserted at the call site.
    """
    try:
        body = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None
    for key in ("Message", "message"):
        if key in body:
            return body[key]
    return None


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A resource policy that Allows only one method ARN implicitly denies another configured path
    on the deployed stage with 403 "not authorized to perform: execute-api:Invoke", and clearing
    the policy makes the same path serve 200."""
    ag = ctx.client("apigateway")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    api_id = _create_api(ctx, ag)
    allowed_id = _child(ctx, ag, api_id, "allowed")
    blocked_id = _child(ctx, ag, api_id, "blocked")
    _mock_method(ag, api_id, allowed_id, "GET", '{"marker":"allowed-route"}')
    _mock_method(ag, api_id, blocked_id, "GET", '{"marker":"blocked-route"}')

    # Allow exactly one method ARN. /blocked is absent => implicit deny.
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": (
                f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/GET/allowed"
            ),
        }],
    }
    ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/policy",
                          "value": json.dumps(policy)}],
    )
    stored = ag.get_rest_api(restApiId=api_id).get("policy") or ""
    assert "execute-api:Invoke" in stored and api_id in stored, (
        f"precondition: the resource policy must round-trip on GetRestApi (AWS returns "
        f"it as an escaped JSON string), got {stored!r}"
    )

    # Deploy only after the policy is attached: a resource policy takes effect with the
    # next deployment, so this ordering leaves no ambiguity about which state is live.
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    allowed_url = _apigw_url(ctx, api_id, stage, "/allowed")
    blocked_url = _apigw_url(ctx, api_id, stage, "/blocked")
    _, _, text = _poll_http(
        allowed_url, lambda s, h, t: s == 200,
        description=f"GET {allowed_url} (the single Allowed method ARN) to serve 200",
    )
    assert json.loads(text).get("marker") == "allowed-route", (
        f"precondition: the allowed route must serve its mapped body, got {text!r}"
    )

    status, _, text = _http("GET", blocked_url)
    assert status == 403, (
        f"expected 403 for GET /blocked, which is a fully configured route that the "
        f"resource policy does not Allow, got {status}: {text!r}"
    )
    # The resource-policy denial is an IAM-shaped body under a CAPITALISED `Message` key, unlike
    # the gateway's own lowercase-`message` 403s. Pinning the key matters because it is how a
    # caller tells an authorization denial apart from a routing failure without parsing prose.
    body = json.loads(text)
    assert "Message" in body and "message" not in body, (
        f"the resource-policy denial body uses the capitalised IAM `Message` key, got "
        f"{sorted(body)} in {text!r}"
    )
    denial = _message(text) or ""
    assert _NOT_AUTHORIZED in denial, (
        f'expected the resource-policy denial message to contain '
        f'"{_NOT_AUTHORIZED}", got {text!r}'
    )
    # It says WHY: no resource-based policy allowed the action. That clause distinguishes an
    # unlisted-ARN denial from an explicit Deny statement, which is the diagnostic a caller acts
    # on, and it names the anonymous caller rather than an IAM principal (authorizationType NONE).
    assert denial.startswith("User: anonymous is not authorized to perform:"), (
        f"the denial must name the anonymous caller, got {denial!r}"
    )
    assert "because no resource-based policy allows the execute-api:Invoke action" in denial, (
        f"the denial must say the resource policy is what failed to allow the call, got "
        f"{denial!r}"
    )
    # And it echoes the execute-api ARN of the exact method that was refused -- with the account
    # id MASKED to its last four digits, which is why this is a regex and not a string compare.
    assert re.search(
        r"on resource: arn:aws:execute-api:"
        + re.escape(ctx.region)
        + r":\*{8}\d{4}:"
        + re.escape(f"{api_id}/{stage}/GET/blocked")
        + r"\b",
        denial,
    ), (
        f"the denial must name the refused method's execute-api ARN with the account id masked "
        f"to its last 4 digits, got {denial!r}"
    )
    assert "Missing Authentication Token" not in denial, (
        f"the 403 must be an authorization denial, not the unrouted-path "
        f"MISSING_AUTHENTICATION_TOKEN response: /blocked is a configured route, "
        f"got {text!r}"
    )
    assert "blocked-route" not in (text or ""), (
        f"the integration behind /blocked must not run when the resource policy "
        f"denies the request, got {text!r}"
    )

    # Control: the deny is ARN-scoped, not a whole-stage outage.
    status, _, text = _http("GET", allowed_url)
    assert status == 200 and json.loads(text).get("marker") == "allowed-route", (
        f"control: the allowed route must still serve after the denial, "
        f"got {status}: {text!r}"
    )

    # Causality: with the policy cleared and redeployed, the same path serves 200 —
    # proving the 403 came from the policy and not from broken routing.
    ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/policy", "value": ""}],
    )
    ag.create_deployment(restApiId=api_id, stageName=stage)
    _poll_http(
        blocked_url, lambda s, h, t: s == 200 and "blocked-route" in t,
        description=(
            f"GET {blocked_url} to serve 200 once the resource policy is cleared and "
            f"the api redeployed (proving the 403 was policy-caused)"
        ),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
