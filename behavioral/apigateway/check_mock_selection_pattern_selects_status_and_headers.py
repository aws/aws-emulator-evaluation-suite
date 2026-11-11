"""mock-selection-pattern-selects-status-and-headers."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "mock-selection-pattern-selects-status-and-headers"
GROUP = 'methods-integrations'
SERVICES = ['apigateway']

# A MOCK integration's request template decides the integration status code; the
# integration responses' selectionPattern then routes it. "" is the default (success)
# mapping, "5\d{2}" matches the 500 branch.
_REQUEST_TEMPLATE = (
    '#if($input.params(\'scope\') == "internal")\n'
    '{"statusCode": 200}\n'
    '#else\n'
    '{"statusCode": 500}\n'
    '#end'
)


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
    touch of a freshly deployed stage polls to a condition with a bounded deadline
    rather than sleeping a fixed amount."""
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """At a deployed stage, selectionPattern routes a MOCK integration's status to the matching
    method response: the error branch answers a real 500, and each branch maps its own body
    and its own static X-Sim-Route header."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    resource_id = _child(ctx, ag, api_id, "select")

    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.scope": False},
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": _REQUEST_TEMPLATE},
    )
    for status_code in ("200", "500"):
        ag.put_method_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET",
            statusCode=status_code,
            responseParameters={"method.response.header.X-Sim-Route": True},
        )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"route":"internal"}'},
        responseParameters={"method.response.header.X-Sim-Route": "'internal'"},
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="500",
        selectionPattern="5\\d{2}",
        responseTemplates={"application/json": '{"route":"external"}'},
        responseParameters={"method.response.header.X-Sim-Route": "'external'"},
    )
    stored = ag.get_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="500",
    )
    assert stored.get("selectionPattern") == "5\\d{2}", (
        f"precondition: the 500 branch's selectionPattern must round-trip, got "
        f"{stored.get('selectionPattern')!r}"
    )

    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage = f"s{_unique_token()}"
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: ag.delete_stage(restApiId=api_id, stageName=stage))

    base_url = _apigw_url(ctx, api_id, stage, "/select")

    # scope=internal -> the mock returns statusCode 200 -> the "" (default) mapping.
    status, headers, text = _poll_http(
        base_url + "?scope=internal", lambda s, h, t: s == 200,
        description=f"GET {base_url}?scope=internal to be served the 200 branch",
    )
    assert json.loads(text) == {"route": "internal"}, (
        f"expected the 200 integration response's template body, got {text!r}"
    )
    assert headers.get("x-sim-route") == "internal", (
        f"expected the 200 integration response's static header mapping "
        f"X-Sim-Route: internal, got {headers.get('x-sim-route')!r}"
    )

    # Any other scope -> the mock returns statusCode 500 -> the "5\d{2}" mapping.
    status, headers, text = _http("GET", base_url + "?scope=external")
    assert status == 500, (
        f"expected the selectionPattern 5\\d{{2}} branch to surface as a real 500 on "
        f"the wire, got {status}: {text!r}"
    )
    assert json.loads(text) == {"route": "external"}, (
        f"expected the 500 integration response's template body, got {text!r}"
    )
    assert headers.get("x-sim-route") == "external", (
        f"expected the 500 integration response's own static header mapping "
        f"X-Sim-Route: external (header mapping is per integration response, not "
        f"per method), got {headers.get('x-sim-route')!r}"
    )

    # Control: the branch is input-driven and repeatable, not sticky per method.
    status, headers, text = _http("GET", base_url + "?scope=internal")
    assert status == 200 and headers.get("x-sim-route") == "internal", (
        f"control: the 200 branch must be selected again for scope=internal, got "
        f"{status} / X-Sim-Route={headers.get('x-sim-route')!r}: {text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
