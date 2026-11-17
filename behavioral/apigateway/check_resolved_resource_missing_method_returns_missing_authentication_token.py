"""resolved-resource-missing-method-returns-missing-authentication-token."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "resolved-resource-missing-method-returns-missing-authentication-token"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]

_MISSING_AUTH_TOKEN = (403, "Missing Authentication Token")


def _token(length=10) -> str:
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


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


def _root_id(ag, api_id: str) -> str:
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _child(ctx, ag, api_id: str, parent_id: str, path_part: str) -> str:
    """A child resource under parent_id (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=parent_id, pathPart=path_part
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id))
    return resource_id


def _mock_method(ctx, ag, api_id: str, resource_id: str, http_method: str, body: dict) -> None:
    """A fully wired MOCK method (registered for teardown) answering a fixed JSON body."""
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE",
    )
    ctx.on_cleanup(
        lambda: ag.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method)
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
        selectionPattern="", responseTemplates={"application/json": json.dumps(body)},
    )


def _http(method: str, url: str) -> tuple:
    """(status, body text) of one unsigned HTTP request."""
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _message(text: str):
    """The `message` field of an execute-api gateway response body, or None."""
    try:
        return json.loads(text).get("message")
    except (ValueError, AttributeError):
        return None


def _poll_until(method: str, url: str, matches, *, timeout_s=180.0, interval_s=3.0):
    """Re-issue a request until matches(status, text), since a freshly (re-)deployed
    stage becomes servable asynchronously; returns the last (status, text)."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, text = _http(method, url)
        if matches(status, text) or time.monotonic() >= deadline:
            return status, text
        time.sleep(interval_s)


def _expect_refusal(method: str, url: str, expected: tuple) -> None:
    """Assert the stage answers exactly `expected` (status, message) for method/url.

    A 200 is the strongest possible mismatch (AWS refused what the target accepted), so
    it is never swallowed into a generic "wrong status" message.
    """
    want_status, want_message = expected
    status, text = _poll_until(method, url, lambda s, t: s == want_status)
    if status == 200:
        raise AssertionError(
            f"expected {method} {url} to be refused with {expected!r}, but it was served: {text!r}"
        )
    assert status == want_status, (
        f"expected status {want_status} for {method} {url}, got {status}: {text!r}"
    )
    assert _message(text) == want_message, (
        f"expected body message {want_message!r} for {method} {url}, got {text!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A literal resource wins a method only when it declares that method, falls through
    to a parameterised sibling that declares one it omits, and a method neither resource
    declares returns the exact 403 Missing Authentication Token body for that one route.
    """
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        policy=_invoke_policy(ctx),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))

    orders_id = _child(ctx, ag, api_id, _root_id(ag, api_id), "orders")
    pending_id = _child(ctx, ag, api_id, orders_id, "pending")
    param_id = _child(ctx, ag, api_id, orders_id, "{orderId}")

    # The literal resource declares GET and POST; the parameterised sibling declares
    # GET and PUT. Neither declares DELETE.
    _mock_method(ctx, ag, api_id, pending_id, "GET", {"handler": "pending-get"})
    _mock_method(ctx, ag, api_id, pending_id, "POST", {"handler": "pending-post"})
    _mock_method(ctx, ag, api_id, param_id, "GET",
                 {"handler": "by-id-get", "orderId": "$input.params('orderId')"})
    _mock_method(ctx, ag, api_id, param_id, "PUT",
                 {"handler": "by-id-put", "orderId": "$input.params('orderId')"})

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_token()}"
    ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    base = ctx.rest_api_url(api_id, stage).rstrip("/")
    pending_url = f"{base}/orders/pending"
    by_id_url = f"{base}/orders/555"

    # The literal resource wins for a method it declares, even though the parameterised
    # sibling declares the same method.
    status, text = _poll_until(
        "GET", pending_url, lambda s, t: s == 200 and _message(t) is None,
    )
    assert status == 200, f"expected 200 serving the configured GET, got {status}: {text!r}"
    body = json.loads(text)
    assert body == {"handler": "pending-get"}, (
        f"expected GET /orders/pending to be served by the literal resource's own GET, "
        f"got {body!r}"
    )

    # Control: the parameterised sibling still serves GET on a path with no literal of
    # its own, binding the path segment into {orderId}.
    status, text = _http("GET", by_id_url)
    assert status == 200, f"expected 200 from the parameterised resource, got {status}: {text!r}"
    body = json.loads(text)
    assert body == {"handler": "by-id-get", "orderId": "555"}, (
        f"expected GET /orders/555 served by the parameterised resource with orderId='555', "
        f"got {body!r}"
    )

    # The literal resource also serves a method the parameterised sibling never
    # declared at all.
    status, text = _http("POST", pending_url)
    assert status == 200, f"expected 200 from the literal resource's own POST, got {status}: {text!r}"
    body = json.loads(text)
    assert body == {"handler": "pending-post"}, (
        f"expected POST /orders/pending served by the literal resource's POST, got {body!r}"
    )

    # The literal resource does not declare PUT, so PUT /orders/pending falls through to
    # the parameterised sibling, which does declare PUT, binding 'pending' into {orderId}.
    status, text = _http("PUT", pending_url)
    assert status == 200, (
        f"expected 200 from the parameterised sibling (the literal resource has no PUT), "
        f"got {status}: {text!r}"
    )
    body = json.loads(text)
    assert body == {"handler": "by-id-put", "orderId": "pending"}, (
        f"expected PUT /orders/pending to fall through to the parameterised resource's PUT "
        f"with orderId='pending', got {body!r}"
    )

    # Neither the literal resource nor the parameterised sibling declares DELETE: the
    # path resolves, but no resource on it answers this method, so the stage returns the
    # exact Missing Authentication Token gateway response rather than 404 or a fallback.
    _expect_refusal("DELETE", pending_url, _MISSING_AUTH_TOKEN)

    # Control: the refusal is scoped to the one undeclared method, not a stage outage.
    status, text = _http("GET", pending_url)
    assert status == 200, f"control: GET /orders/pending must still serve, got {status}: {text!r}"
    body = json.loads(text)
    assert body == {"handler": "pending-get"}, (
        f"control: expected the literal resource's GET body after the refusal, got {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
